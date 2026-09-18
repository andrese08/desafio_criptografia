import os
import sys
import getpass
import struct
from cryptography.hazmat.primitives import cmac
from cryptography.hazmat.primitives.ciphers import algorithms, Cipher, modes
try:
    from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
except ImportError:
    from cryptography.hazmat.primitives.ciphers.algorithms import TripleDES
from psec import tr31


def limpiar_hex(valor):
    """Elimina espacios en blanco accidentales de las cadenas hexadecimales."""
    return valor.replace(" ", "").strip()


def aes_cmac(key, data):
    """Calcula el AES-CMAC de un set de datos utilizando la librería cryptography."""
    c = cmac.CMAC(algorithms.AES(key))
    c.update(data)
    return c.finalize()


# ---------------------------------------------------------------------------
# Derivación de llaves TR-31 Versión D (ANSI X9.143, "AES Key Derivation
# Binding Method"). Idéntica a key_exchange.py; ver TR31_documentacion.md
# para el detalle completo de cómo se verificó cada byte de este formato.
# ---------------------------------------------------------------------------

_KDI_TABLE = {
    16: {  # AES-128
        "kbek": [bytes([0x01, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x80])],
        "kbak": [bytes([0x01, 0x00, 0x01, 0x00, 0x00, 0x02, 0x00, 0x80])],
    },
    24: {  # AES-192
        "kbek": [bytes([0x01, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0xC0]),
                 bytes([0x02, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0xC0])],
        "kbak": [bytes([0x01, 0x00, 0x01, 0x00, 0x00, 0x03, 0x00, 0xC0]),
                 bytes([0x02, 0x00, 0x01, 0x00, 0x00, 0x03, 0x00, 0xC0])],
    },
    32: {  # AES-256
        "kbek": [bytes([0x01, 0x00, 0x00, 0x00, 0x00, 0x04, 0x01, 0x00]),
                 bytes([0x02, 0x00, 0x00, 0x00, 0x00, 0x04, 0x01, 0x00])],
        "kbak": [bytes([0x01, 0x00, 0x01, 0x00, 0x00, 0x04, 0x01, 0x00]),
                 bytes([0x02, 0x00, 0x01, 0x00, 0x00, 0x04, 0x01, 0x00])],
    },
}


def derivar_llaves_tr31_version_d(kbpk):
    """Deriva (KBEK, KBAK) para TR-31 Versión D. Ambas del mismo tamaño que kbpk."""
    n = len(kbpk)
    if n not in _KDI_TABLE:
        raise ValueError(f"Tamaño de KBPK no soportado para Versión D: {n} bytes")
    kbek = b"".join(aes_cmac(kbpk, bloque) for bloque in _KDI_TABLE[n]["kbek"])[:n]
    kbak = b"".join(aes_cmac(kbpk, bloque) for bloque in _KDI_TABLE[n]["kbak"])[:n]
    return kbek, kbak


def envolver_tr31_version_d(kbpk, header_ascii, llave_a_envolver):
    """Sella (wrap) una llave en un key block TR-31 Versión D (MAC como IV)."""
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
    """
    Desenvuelve (unwrap) un key block TR-31 Versión D generado por
    envolver_tr31_version_d. Se usa como AUTOVERIFICACIÓN inmediatamente
    después de generar un bloque (por ejemplo la PEK en export-pek), sin
    depender de `psec` — solo con `cryptography`.
    """
    header = block_hex[:16].encode("ascii")
    rest = bytes.fromhex(block_hex[16:])
    mac_recibido = rest[-16:]
    datos_cifrados = rest[:-16]

    kbek, kbak = derivar_llaves_tr31_version_d(kbpk)

    cipher = Cipher(algorithms.AES(kbek), modes.CBC(mac_recibido))
    datos_en_claro = cipher.decryptor().update(datos_cifrados)

    mac_calculado = aes_cmac(kbak, header + datos_en_claro)
    if mac_calculado != mac_recibido:
        raise ValueError("Autoverificación fallida: el MAC no coincide (bloque corrupto o KEK incorrecta).")

    longitud_bits = int.from_bytes(datos_en_claro[:2], "big")
    longitud_bytes = longitud_bits // 8
    llave = datos_en_claro[2:2 + longitud_bytes]
    return header.decode("ascii"), llave


def recombinar_y_validar_kek(comp1_raw, comp2_raw, kcv_esperado):
    """Realiza la operación XOR y valida el CMAC-KCV de la KEK AES-256."""
    c1 = limpiar_hex(comp1_raw)
    c2 = limpiar_hex(comp2_raw)

    bytes1 = bytes.fromhex(c1)
    bytes2 = bytes.fromhex(c2)

    if len(bytes1) != 32 or len(bytes2) != 32:
        raise ValueError("Cada componente debe medir exactamente 32 bytes para AES-256.")

    kek_bytes = bytes(b1 ^ b2 for b1, b2 in zip(bytes1, bytes2))
    kcv_calculado = aes_cmac(kek_bytes, b'\x00' * 16)[:3].hex().upper()

    if kcv_calculado != kcv_esperado.upper():
        raise ValueError(f"❌ Error de KEK: KCV calculado {kcv_calculado} no coincide con el esperado {kcv_esperado}")

    return kek_bytes


def procesar_export_pek(kek_component_1, kek_component_2, kek_kcv, ruta_salida):
    """Lógica del proceso 'exportar PEK' (idéntica a cmd_export_pek de key_exchange.py)."""
    kek_bytes = recombinar_y_validar_kek(kek_component_1, kek_component_2, kek_kcv)
    print("[✓] KEK validada exitosamente mediante CMAC-KCV.")

    pek_bytes = os.urandom(16)

    pek_full = pek_bytes + pek_bytes[:8]
    cipher_tdes = Cipher(TripleDES(pek_full), modes.ECB())
    kcv_pek = cipher_tdes.encryptor().update(b'\x00' * 8)[:3].hex().upper()

    longitud_payload = 2 + len(pek_bytes)
    relleno = (-longitud_payload) % 16
    longitud_total = 16 + (longitud_payload + relleno) * 2 + 32

    header_str = f"D{longitud_total:04d}P0TB00E0000"

    block_hex = envolver_tr31_version_d(kek_bytes, header_str, pek_bytes)

    # Autoverificación: desenvolver el bloque recién generado (sin depender
    # de psec) y confirmar que la PEK y el KCV recuperados coinciden con
    # los originales, antes de darlo por bueno.
    _, pek_verificada = desenvolver_tr31_version_d(kek_bytes, block_hex)
    pek_verificada_full = pek_verificada + pek_verificada[:8]
    kcv_verificado = Cipher(TripleDES(pek_verificada_full), modes.ECB()).encryptor().update(b'\x00' * 8)[:3].hex().upper()
    autoverificacion_ok = (pek_verificada == pek_bytes) and (kcv_verificado == kcv_pek)

    with open(ruta_salida, "w") as f:
        f.write(block_hex)

    print("\n" + "=" * 70)
    print("                 PROCESAMIENTO DE EXPORTACIÓN PEK")
    print("=" * 70)
    print(f"TR-31 PEK Block guardado en: {ruta_salida}")
    print(f"Criptograma TR-31:  {block_hex}")
    print(f"KCV de la PEK TDES: {kcv_pek}")
    print("-" * 70)
    if autoverificacion_ok:
        print(f"[✓] Autoverificación: el bloque se desenvuelve correctamente y el KCV coincide ({kcv_verificado}).")
    else:
        print(f"❌ Autoverificación FALLIDA: KCV recuperado {kcv_verificado} ≠ KCV original {kcv_pek}.")
    print("=" * 70)


def procesar_import_bdk(kek_component_1, kek_component_2, kek_kcv, bdk_keyblock, bdk_kcv):
    """Lógica del proceso 'importar BDK' (idéntica a cmd_import_bdk de key_exchange.py)."""
    kek_bytes = recombinar_y_validar_kek(kek_component_1, kek_component_2, kek_kcv)
    print("[✓] KEK validada exitosamente mediante CMAC-KCV.")

    block_hex = limpiar_hex(bdk_keyblock)
    header_info, bdk_bytes = tr31.unwrap(kek_bytes, block_hex)

    bdk_full = bdk_bytes + bdk_bytes[:8] if len(bdk_bytes) == 16 else bdk_bytes
    cipher_tdes = Cipher(TripleDES(bdk_full), modes.ECB())
    kcv_calculado = cipher_tdes.encryptor().update(b'\x00' * 8)[:3].hex().upper()

    print("\n" + "=" * 70)
    print("                 PROCESAMIENTO DE IMPORTACIÓN BDK")
    print("=" * 70)
    print(f"Encabezado TR-31 BDK:  {block_hex[:16]}")
    print(f"BDK en Claro (Hex):    {bdk_bytes.hex().upper()}")
    print(f"KCV BDK Calculado:     {kcv_calculado}")
    print(f"KCV BDK Esperado:      {bdk_kcv.upper()}")

    if kcv_calculado == bdk_kcv.upper():
        print("[✓] VALIDACIÓN EXITOSA: La BDK es íntegra y correcta.")
        print("=" * 70)
    else:
        print("❌ VALIDACIÓN FALLIDA: Los KCV de la BDK no coinciden.")
        print("=" * 70)
        sys.exit(1)


# ---------------------------------------------------------------------------
# Entrada interactiva por consola
# ---------------------------------------------------------------------------

def pedir_valor(etiqueta):
    """Pide un valor de texto por consola, reintentando si llega vacío."""
    while True:
        valor = input(f"{etiqueta}: ").strip()
        if valor:
            return valor
        print("  ⚠ El valor no puede estar vacío. Intenta de nuevo.")


def pedir_secreto(etiqueta):
    """
    Pide un valor SENSIBLE por consola sin mostrarlo en pantalla (getpass),
    para los componentes de la KEK. A diferencia de pedir_valor(), esto
    evita que el componente quede visible en el scrollback de la terminal,
    en una grabación de sesión o en una pantalla compartida mientras se
    teclea — el mismo riesgo de "Information Disclosure" señalado en el
    análisis de seguridad para los campos de componente de la KEK.
    """
    while True:
        try:
            valor = getpass.getpass(f"{etiqueta}: ").strip()
        except (EOFError, KeyboardInterrupt):
            raise
        if valor:
            return valor
        print("  ⚠ El valor no puede estar vacío. Intenta de nuevo.")


def elegir_proceso():
    """Muestra el menú de procesos disponibles y devuelve la opción elegida."""
    print("=" * 70)
    print("   MÓDULO DE INTERCAMBIO DE LLAVES TR-31 (ANSI X9.143)")
    print("   MODO INTERACTIVO")
    print("=" * 70)
    print("¿Qué proceso deseas ejecutar?")
    print("  1) Exportar PEK  (generar una PEK y entregarla en key block TR-31)")
    print("  2) Importar BDK  (desenvolver y validar un key block TR-31 de la BDK)")
    print()
    while True:
        opcion = input("Elige una opción [1/2]: ").strip()
        if opcion in ("1", "2"):
            return opcion
        print("  ⚠ Opción inválida. Escribe 1 o 2.")


def main():
    opcion = elegir_proceso()

    print("\nAhora ingresa los datos de la KEK (compartidos por ambos procesos):\n")
    kek_component_1 = pedir_secreto("Componente 1 de la KEK (hex) [no se mostrará en pantalla]")
    kek_component_2 = pedir_secreto("Componente 2 de la KEK (hex) [no se mostrará en pantalla]")
    kek_kcv = pedir_valor("KCV esperado de la KEK (hex, 6 caracteres)")

    try:
        if opcion == "1":
            print()
            ruta_salida = pedir_valor("Ruta del archivo de salida para el key block de la PEK")
            procesar_export_pek(kek_component_1, kek_component_2, kek_kcv, ruta_salida)
        else:
            print()
            bdk_keyblock = pedir_valor("Key block TR-31 de la BDK (hex)")
            bdk_kcv = pedir_valor("KCV esperado de la BDK (hex, 6 caracteres)")
            procesar_import_bdk(kek_component_1, kek_component_2, kek_kcv, bdk_keyblock, bdk_kcv)
    except Exception as e:
        print(f"❌ Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()