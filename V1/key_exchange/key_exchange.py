import argparse
import os
import sys
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
# Binding Method"). Verificado contra el vector de prueba público del crate
# `paysec` (AES-256) y contra el key block real de la BDK entregado.
#
# Formato de los 8 bytes de "datos de derivación" (uno por cada bloque CMAC
# necesario):
#   byte 0       -> Contador (1, y 2 si la llave derivada necesita más de
#                   un bloque CMAC de 16 bytes, p.ej. AES-192/256)
#   byte 1       -> 0x00 (separador)
#   byte 2       -> Indicador de uso: 0x00 = KBEK (cifrado), 0x01 = KBAK (MAC)
#   byte 3       -> 0x00 (separador)
#   byte 4       -> 0x00 (indicador de algoritmo, AES)
#   byte 5       -> "código" de tamaño de llave (2/3/4 = 128/192/256 bits)
#   bytes 6-7    -> longitud de la llave derivada en BITS (big-endian)
#
# La llave derivada (KBEK o KBAK) SIEMPRE tiene el mismo tamaño que la KBPK
# (la KEK, en este caso), no un tamaño fijo de 128 bits. Por eso, para una
# KEK AES-256 hacen falta DOS llamadas a CMAC (contador 1 y 2) concatenadas.
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
    """
    Sella (wrap) una llave en un key block TR-31 Versión D.

    Orden de operaciones (verificado contra un key block TR-31 real):
      1. Construir el campo de datos en claro: [longitud en bits, 2 bytes] + llave + relleno ALEATORIO.
      2. Calcular el MAC = CMAC(KBAK, header || datos_en_claro)   <- MAC sobre el TEXTO EN CLARO, no el cifrado.
      3. Cifrar los datos en claro con AES-CBC usando KBEK, usando el propio MAC como IV.
      4. El bloque final es: header || datos_cifrados || MAC.
    """
    kbek, kbak = derivar_llaves_tr31_version_d(kbpk)

    longitud_bits = len(llave_a_envolver) * 8
    datos_en_claro = struct.pack(">H", longitud_bits) + llave_a_envolver

    # Relleno ALEATORIO (no ceros) hasta el siguiente múltiplo de 16 bytes.
    relleno = os.urandom((-len(datos_en_claro)) % 16)
    datos_en_claro += relleno

    header_bytes = header_ascii.encode("ascii")

    # Paso 2: MAC sobre header + texto en claro (NO sobre el cifrado)
    mac = aes_cmac(kbak, header_bytes + datos_en_claro)

    # Paso 3: cifrar usando el MAC como IV (no un IV en ceros)
    cipher = Cipher(algorithms.AES(kbek), modes.CBC(mac))
    encryptor = cipher.encryptor()
    datos_cifrados = encryptor.update(datos_en_claro) + encryptor.finalize()

    return header_ascii + datos_cifrados.hex().upper() + mac.hex().upper()


def desenvolver_tr31_version_d(kbpk, block_hex):
    """
    Desenvuelve (unwrap) un key block TR-31 Versión D generado por
    envolver_tr31_version_d. Se usa como AUTOVERIFICACIÓN inmediatamente
    después de generar un bloque (por ejemplo la PEK en export-pek), sin
    depender de `psec` — solo con `cryptography`, siguiendo exactamente el
    proceso inverso al de wrap: descifrar con el MAC recibido como IV, y
    recalcular el MAC sobre el texto en claro para confirmar integridad.
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


def cmd_export_pek(args):
    """Genera una PEK TDES y la entrega envuelta en un key block TR-31 Versión D."""
    try:
        # 1. Recombinar KEK
        kek_bytes = recombinar_y_validar_kek(args.kek_component_1, args.kek_component_2, args.kek_kcv)
        print("[✓] KEK validada exitosamente mediante CMAC-KCV.")

        # 2. Generar una PEK TDES aleatoria de 16 bytes (2-key TDES)
        pek_bytes = os.urandom(16)

        # KCV estándar para llaves TDES: cifrar 8 bytes de ceros en modo ECB
        pek_full = pek_bytes + pek_bytes[:8]
        cipher_tdes = Cipher(TripleDES(pek_full), modes.ECB())
        kcv_pek = cipher_tdes.encryptor().update(b'\x00' * 8)[:3].hex().upper()

        # 3. Calcular la longitud REAL del bloque antes de fijar el header
        #    (el bug anterior dejaba un valor fijo "0072" que no correspondía
        #    al tamaño real del bloque generado).
        longitud_payload = 2 + len(pek_bytes)                     # campo longitud + llave
        relleno = (-longitud_payload) % 16
        longitud_total = 16 + (longitud_payload + relleno) * 2 + 32  # header + datos(hex) + mac(hex)

        # Key usage "P0" = PIN Encryption Key, algoritmo "T" = TDES,
        # modo de uso "B" = Encrypt & Decrypt, exportable "E".
        header_str = f"D{longitud_total:04d}P0TB00E0000"

        # 4. Envolver la PEK en TR-31 Versión D usando la KEK como KBPK
        block_hex = envolver_tr31_version_d(kek_bytes, header_str, pek_bytes)

        # 5. Autoverificación: desenvolver el bloque recién generado (sin
        #    depender de psec) y confirmar que la PEK y el KCV recuperados
        #    coinciden con los originales, antes de darlo por bueno.
        _, pek_verificada = desenvolver_tr31_version_d(kek_bytes, block_hex)
        pek_verificada_full = pek_verificada + pek_verificada[:8]
        kcv_verificado = Cipher(TripleDES(pek_verificada_full), modes.ECB()).encryptor().update(b'\x00' * 8)[:3].hex().upper()
        autoverificacion_ok = (pek_verificada == pek_bytes) and (kcv_verificado == kcv_pek)

        # Guardar en archivo de salida especificado
        with open(args.out, "w") as f:
            f.write(block_hex)

        print("\n" + "=" * 70)
        print("                 PROCESAMIENTO DE EXPORTACIÓN PEK")
        print("=" * 70)
        print(f"TR-31 PEK Block guardado en: {args.out}")
        print(f"Criptograma TR-31:  {block_hex}")
        print(f"KCV de la PEK TDES: {kcv_pek}")
        print("-" * 70)
        if autoverificacion_ok:
            print(f"[✓] Autoverificación: el bloque se desenvuelve correctamente y el KCV coincide ({kcv_verificado}).")
        else:
            print(f"❌ Autoverificación FALLIDA: KCV recuperado {kcv_verificado} ≠ KCV original {kcv_pek}.")
        print("=" * 70)

    except Exception as e:
        print(f"❌ Error en export-pek: {e}", file=sys.stderr)
        sys.exit(1)


def cmd_import_bdk(args):
    """Desenvuelve el bloque TR-31 de la BDK usando tr31.unwrap de psec."""
    try:
        # 1. Recombinar KEK
        kek_bytes = recombinar_y_validar_kek(args.kek_component_1, args.kek_component_2, args.kek_kcv)
        print("[✓] KEK validada exitosamente mediante CMAC-KCV.")

        # 2. Desenvolver el bloque TR-31 de la BDK usando psec
        block_hex = limpiar_hex(args.bdk_keyblock)
        header_info, bdk_bytes = tr31.unwrap(kek_bytes, block_hex)

        # 3. Calcular KCV de la BDK TDES extraída (Cifrado TripleDES sobre 8 bytes de ceros)
        bdk_full = bdk_bytes + bdk_bytes[:8] if len(bdk_bytes) == 16 else bdk_bytes
        cipher_tdes = Cipher(TripleDES(bdk_full), modes.ECB())
        kcv_calculado = cipher_tdes.encryptor().update(b'\x00' * 8)[:3].hex().upper()

        print("\n" + "=" * 70)
        print("                 PROCESAMIENTO DE IMPORTACIÓN BDK")
        print("=" * 70)
        print(f"Encabezado TR-31 BDK:  {block_hex[:16]}")
        print(f"BDK en Claro (Hex):    {bdk_bytes.hex().upper()}")
        print(f"KCV BDK Calculado:     {kcv_calculado}")
        print(f"KCV BDK Esperado:      {args.bdk_kcv.upper()}")

        if kcv_calculado == args.bdk_kcv.upper():
            print("[✓] VALIDACIÓN EXITOSA: La BDK es íntegra y correcta.")
            print("=" * 70)
        else:
            print("❌ VALIDACIÓN FALLIDA: Los KCV de la BDK no coinciden.")
            print("=" * 70)
            sys.exit(1)

    except Exception as e:
        print(f"❌ Error en import-bdk: {e}", file=sys.stderr)
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description="Módulo de intercambio de llaves financieras (TR-31)")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Comando export-pek
    parser_export = subparsers.add_parser("export-pek")
    parser_export.add_argument("--kek-component-1", required=True)
    parser_export.add_argument("--kek-component-2", required=True)
    parser_export.add_argument("--kek-kcv", required=True)
    parser_export.add_argument("--out", required=True)
    parser_export.set_defaults(func=cmd_export_pek)

    # Comando import-bdk
    parser_import = subparsers.add_parser("import-bdk")
    parser_import.add_argument("--kek-component-1", required=True)
    parser_import.add_argument("--kek-component-2", required=True)
    parser_import.add_argument("--kek-kcv", required=True)
    parser_import.add_argument("--bdk-keyblock", required=True)
    parser_import.add_argument("--bdk-kcv", required=True)
    parser_import.set_defaults(func=cmd_import_bdk)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
