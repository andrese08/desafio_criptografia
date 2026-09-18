"""
Núcleo criptográfico compartido por la aplicación web (v3).

Contiene, sin cambios de lógica respecto a las versiones ya validadas
(dukpt_fixed.py / key_exchange.py):
  - El motor de descifrado DUKPT (ANSI X9.24).
  - La derivación y el sellado/desellado TR-31 Versión D (ANSI X9.143).
  - La reconstrucción y validación de la KEK.

Este módulo NO imprime ni loguea ningún valor sensible completo — solo
devuelve estructuras de datos (dicts) que la capa web decide cómo mostrar.
La función `mask_value` es la única forma permitida de mostrar un componente
de la KEK en pantalla o en logs.
"""

import os
import struct
from cryptography.hazmat.primitives import cmac
from cryptography.hazmat.primitives.ciphers import algorithms, Cipher, modes
try:
    from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
except ImportError:
    from cryptography.hazmat.primitives.ciphers.algorithms import TripleDES


# ---------------------------------------------------------------------------
# Utilidades comunes
# ---------------------------------------------------------------------------

def limpiar_hex(valor):
    """Elimina espacios en blanco accidentales de una cadena hexadecimal."""
    return (valor or "").replace(" ", "").strip()


def mask_value(valor, visible=4):
    """
    Enmascara un valor dejando visibles solo los últimos `visible`
    caracteres. Es la ÚNICA forma permitida de mostrar un componente de la
    KEK en pantalla o de escribirlo en un log — el valor completo nunca debe
    imprimirse ni registrarse en ningún punto de la aplicación.
    """
    if not valor:
        return ""
    v = valor.strip()
    if len(v) <= visible:
        return "•" * len(v)
    return "•" * (len(v) - visible) + v[-visible:]


class ErrorValidacion(Exception):
    """Error de validación de entrada, pensado para mostrarse tal cual al usuario."""
    pass


# ---------------------------------------------------------------------------
# DUKPT (ANSI X9.24) — idéntico a dukpt_fixed.py, reestructurado para
# devolver datos en vez de imprimir directamente.
# ---------------------------------------------------------------------------

C0_MASK_8 = bytes([0xC0, 0xC0, 0xC0, 0xC0, 0x00, 0x00, 0x00, 0x00])

_VARIANTES_DUKPT = {
    "Current Key (sin variante)": (),
    "PIN Encryption Key": (7, 15),
    "MAC Request Key": (6, 14),
    "MAC Response Key": (4, 12),
    "Data Request Key": (5, 13),
    "Data Response Key": (3, 11),
}


def _aplicar_variante_c0(key_bytes):
    return bytes(b ^ C0_MASK_8[i % 8] for i, b in enumerate(key_bytes))


def _crypto_des(key, block):
    cipher = Cipher(TripleDES(key * 3), modes.ECB())
    return cipher.encryptor().update(block)


def _crypto_3des_enc(key, block):
    if len(key) == 16:
        key = key + key[:8]
    cipher = Cipher(TripleDES(key), modes.ECB())
    return cipher.encryptor().update(block)


def _parse_hex(etiqueta, valor, longitud_bytes_esperada=None):
    limpio = limpiar_hex(valor)
    if not limpio:
        raise ErrorValidacion(f"{etiqueta}: no puede estar vacío.")
    try:
        datos = bytes.fromhex(limpio)
    except ValueError:
        raise ErrorValidacion(f"{etiqueta}: no es un valor hexadecimal válido.")
    if longitud_bytes_esperada is not None and len(datos) != longitud_bytes_esperada:
        raise ErrorValidacion(
            f"{etiqueta}: se esperaban {longitud_bytes_esperada} bytes "
            f"({longitud_bytes_esperada * 2} caracteres hex) y se recibieron {len(datos)}."
        )
    return datos


def ejecutar_descifrado_dukpt(bdk_hex, ksn_hex, ciphertext_hex):
    """
    Ejecuta el descifrado DUKPT completo y devuelve un dict con todos los
    candidatos (6 variantes de llave x 2 modos de cifrado), ordenados por
    qué tanto el resultado "parece texto ASCII imprimible".
    """
    bdk = _parse_hex("BDK", bdk_hex, longitud_bytes_esperada=16)
    ksn = _parse_hex("KSN", ksn_hex, longitud_bytes_esperada=10)
    ciphertext = _parse_hex("Criptograma", ciphertext_hex)

    if len(ciphertext) == 0 or len(ciphertext) % 8 != 0:
        raise ErrorValidacion("Criptograma: la longitud debe ser un múltiplo de 8 bytes.")

    # 1-2. Derivar el IPEK
    ksn_base_ipek = bytearray(ksn[:8])
    ksn_base_ipek[7] &= 0xE0
    ipek_l = _crypto_3des_enc(bdk, bytes(ksn_base_ipek))
    ipek_r = _crypto_3des_enc(_aplicar_variante_c0(bdk), bytes(ksn_base_ipek))
    cur_key = bytearray(ipek_l + ipek_r)

    # 3. Extraer el contador de transacción
    tc = ((ksn[7] & 0x1F) << 16) | (ksn[8] << 8) | ksn[9]

    # 4. Preparar la base de 8 bytes del bucle de llaves futuras
    ksn_loop_base = bytearray(ksn[2:10])
    ksn_loop_base[5] &= 0xE0
    ksn_loop_base[6] = 0x00
    ksn_loop_base[7] = 0x00

    running_tc = 0
    bit_mask = 0x100000
    while bit_mask > 0:
        if tc & bit_mask:
            running_tc |= bit_mask
            msg = bytearray(ksn_loop_base)
            msg[5] |= (running_tc >> 16) & 0x1F
            msg[6] = (running_tc >> 8) & 0xFF
            msg[7] = running_tc & 0xFF

            kl = bytes(cur_key[:8])
            kr = bytes(cur_key[8:16])

            c_input_l = bytes(b ^ m for b, m in zip(kr, msg))
            c_output_l = _crypto_des(kl, c_input_l)
            nxt_l = bytes(b ^ c for b, c in zip(kr, c_output_l))

            kl_m = _aplicar_variante_c0(kl)
            kr_m = _aplicar_variante_c0(kr)
            c_input_r = bytes(b ^ m for b, m in zip(kr_m, msg))
            c_output_r = _crypto_des(kl_m, c_input_r)
            nxt_r = bytes(b ^ c for b, c in zip(kr_m, c_output_r))

            cur_key = bytearray(nxt_r + nxt_l)
        bit_mask >>= 1

    def aplicar_variante(base_key, indices):
        k = bytearray(base_key)
        for i in indices:
            k[i] ^= 0xFF
        return bytes(k)

    candidatos = []
    for nombre, indices in _VARIANTES_DUKPT.items():
        llave = aplicar_variante(cur_key, indices)
        for modo_nombre, modo in (("ECB", modes.ECB()), ("CBC (IV=0)", modes.CBC(bytes(8)))):
            try:
                clave_tdes = llave + llave[:8] if len(llave) == 16 else llave
                cipher = Cipher(TripleDES(clave_tdes), modo)
                claro = cipher.decryptor().update(ciphertext)
            except Exception:
                continue
            imprimibles = sum(1 for b in claro if 0x20 <= b <= 0x7E)
            score = imprimibles / max(len(claro), 1)
            candidatos.append({
                "nombre": nombre,
                "modo": modo_nombre,
                "llave": llave.hex().upper(),
                "hex": claro.hex().upper(),
                "texto": claro.decode("utf-8", errors="ignore").strip(),
                "score": round(score, 3),
            })

    candidatos.sort(key=lambda r: r["score"], reverse=True)
    return {"candidatos": candidatos}


# ---------------------------------------------------------------------------
# TR-31 Versión D (ANSI X9.143) — idéntico a key_exchange.py
# ---------------------------------------------------------------------------

def aes_cmac(key, data):
    c = cmac.CMAC(algorithms.AES(key))
    c.update(data)
    return c.finalize()


_KDI_TABLE = {
    16: {
        "kbek": [bytes([0x01, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x80])],
        "kbak": [bytes([0x01, 0x00, 0x01, 0x00, 0x00, 0x02, 0x00, 0x80])],
    },
    24: {
        "kbek": [bytes([0x01, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0xC0]),
                 bytes([0x02, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0xC0])],
        "kbak": [bytes([0x01, 0x00, 0x01, 0x00, 0x00, 0x03, 0x00, 0xC0]),
                 bytes([0x02, 0x00, 0x01, 0x00, 0x00, 0x03, 0x00, 0xC0])],
    },
    32: {
        "kbek": [bytes([0x01, 0x00, 0x00, 0x00, 0x00, 0x04, 0x01, 0x00]),
                 bytes([0x02, 0x00, 0x00, 0x00, 0x00, 0x04, 0x01, 0x00])],
        "kbak": [bytes([0x01, 0x00, 0x01, 0x00, 0x00, 0x04, 0x01, 0x00]),
                 bytes([0x02, 0x00, 0x01, 0x00, 0x00, 0x04, 0x01, 0x00])],
    },
}


def derivar_llaves_tr31_version_d(kbpk):
    n = len(kbpk)
    if n not in _KDI_TABLE:
        raise ErrorValidacion(f"Tamaño de KEK no soportado para TR-31 Versión D: {n} bytes")
    kbek = b"".join(aes_cmac(kbpk, bloque) for bloque in _KDI_TABLE[n]["kbek"])[:n]
    kbak = b"".join(aes_cmac(kbpk, bloque) for bloque in _KDI_TABLE[n]["kbak"])[:n]
    return kbek, kbak


def envolver_tr31_version_d(kbpk, header_ascii, llave_a_envolver):
    kbek, kbak = derivar_llaves_tr31_version_d(kbpk)
    longitud_bits = len(llave_a_envolver) * 8
    datos_en_claro = struct.pack(">H", longitud_bits) + llave_a_envolver
    relleno = os.urandom((-len(datos_en_claro)) % 16)
    datos_en_claro += relleno
    header_bytes = header_ascii.encode("ascii")
    mac = aes_cmac(kbak, header_bytes + datos_en_claro)
    cipher = Cipher(algorithms.AES(kbek), modes.CBC(mac))
    encryptor = cipher.encryptor()
    datos_cifrados = encryptor.update(datos_en_claro) + encryptor.finalize()
    return header_ascii + datos_cifrados.hex().upper() + mac.hex().upper()


def desenvolver_tr31_version_d(kbpk, block_hex):
    header = block_hex[:16].encode("ascii")
    rest = bytes.fromhex(block_hex[16:])
    mac_recibido = rest[-16:]
    datos_cifrados = rest[:-16]
    kbek, kbak = derivar_llaves_tr31_version_d(kbpk)
    cipher = Cipher(algorithms.AES(kbek), modes.CBC(mac_recibido))
    datos_en_claro = cipher.decryptor().update(datos_cifrados)
    mac_calculado = aes_cmac(kbak, header + datos_en_claro)
    if mac_calculado != mac_recibido:
        raise ErrorValidacion("El MAC del key block no coincide (bloque corrupto o KEK incorrecta).")
    longitud_bits = int.from_bytes(datos_en_claro[:2], "big")
    longitud_bytes = longitud_bits // 8
    llave = datos_en_claro[2:2 + longitud_bytes]
    return header.decode("ascii"), llave


def recombinar_y_validar_kek(comp1_raw, comp2_raw, kcv_esperado):
    c1 = limpiar_hex(comp1_raw)
    c2 = limpiar_hex(comp2_raw)
    kcv_esperado = limpiar_hex(kcv_esperado)

    if not c1 or not c2:
        raise ErrorValidacion("Faltan uno o ambos componentes de la KEK.")
    if not kcv_esperado:
        raise ErrorValidacion("Falta el KCV esperado de la KEK.")

    try:
        bytes1 = bytes.fromhex(c1)
        bytes2 = bytes.fromhex(c2)
    except ValueError:
        raise ErrorValidacion("Alguno de los componentes de la KEK no es hexadecimal válido.")

    if len(bytes1) != 32 or len(bytes2) != 32:
        raise ErrorValidacion("Cada componente debe medir exactamente 32 bytes (64 caracteres hex) para AES-256.")

    kek_bytes = bytes(b1 ^ b2 for b1, b2 in zip(bytes1, bytes2))
    kcv_calculado = aes_cmac(kek_bytes, b"\x00" * 16)[:3].hex().upper()

    if kcv_calculado != kcv_esperado.upper():
        raise ErrorValidacion(
            f"KCV de la KEK no coincide: calculado {kcv_calculado}, esperado {kcv_esperado.upper()}."
        )

    return kek_bytes


def generar_pek_keyblock(kek_bytes):
    """Genera una PEK TDES aleatoria, la sella en TR-31 Versión D y se autoverifica."""
    pek_bytes = os.urandom(16)
    pek_full = pek_bytes + pek_bytes[:8]
    kcv_pek = Cipher(TripleDES(pek_full), modes.ECB()).encryptor().update(b"\x00" * 8)[:3].hex().upper()

    longitud_payload = 2 + len(pek_bytes)
    relleno = (-longitud_payload) % 16
    longitud_total = 16 + (longitud_payload + relleno) * 2 + 32
    header_str = f"D{longitud_total:04d}P0TB00E0000"

    block_hex = envolver_tr31_version_d(kek_bytes, header_str, pek_bytes)

    _, pek_verificada = desenvolver_tr31_version_d(kek_bytes, block_hex)
    pek_verificada_full = pek_verificada + pek_verificada[:8]
    kcv_verificado = Cipher(TripleDES(pek_verificada_full), modes.ECB()).encryptor().update(b"\x00" * 8)[:3].hex().upper()
    autoverificacion_ok = (pek_verificada == pek_bytes) and (kcv_verificado == kcv_pek)

    return {
        "block_hex": block_hex,
        "kcv_pek": kcv_pek,
        "autoverificacion_ok": autoverificacion_ok,
        "kcv_verificado": kcv_verificado,
    }


def importar_bdk_keyblock(kek_bytes, bdk_keyblock_hex, bdk_kcv_esperado):
    """Desenvuelve un key block TR-31 de la BDK usando psec y valida su KCV."""
    from psec import tr31  # se importa aquí para que el resto de la app funcione aunque psec no esté instalado

    block_hex = limpiar_hex(bdk_keyblock_hex)
    if not block_hex:
        raise ErrorValidacion("Falta el key block TR-31 de la BDK.")
    bdk_kcv_esperado = limpiar_hex(bdk_kcv_esperado)
    if not bdk_kcv_esperado:
        raise ErrorValidacion("Falta el KCV esperado de la BDK.")

    try:
        header_info, bdk_bytes = tr31.unwrap(kek_bytes, block_hex)
    except Exception as e:
        raise ErrorValidacion(f"No se pudo desenvolver el key block de la BDK: {e}")

    bdk_full = bdk_bytes + bdk_bytes[:8] if len(bdk_bytes) == 16 else bdk_bytes
    kcv_calculado = Cipher(TripleDES(bdk_full), modes.ECB()).encryptor().update(b"\x00" * 8)[:3].hex().upper()

    validacion_exitosa = (kcv_calculado == bdk_kcv_esperado.upper())

    return {
        "header": block_hex[:16],
        "bdk_hex": bdk_bytes.hex().upper(),
        "kcv_calculado": kcv_calculado,
        "kcv_esperado": bdk_kcv_esperado.upper(),
        "validacion_exitosa": validacion_exitosa,
    }
