import argparse
import sys
from cryptography.hazmat.primitives.ciphers import Cipher, modes
try:
    from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
except ImportError:
    from cryptography.hazmat.primitives.ciphers.algorithms import TripleDES

# Máscara de variante "C0": se aplica solo a los primeros 4 bytes de cada
# mitad de 8 bytes de una llave, NO a los 8 bytes completos.
C0_MASK_8 = bytes([0xC0, 0xC0, 0xC0, 0xC0, 0x00, 0x00, 0x00, 0x00])


def limpiar_hex(valor):
    """Elimina espacios y asegura formato limpio."""
    return valor.replace(" ", "").strip().upper()


def aplicar_variante_c0(key_bytes):
    """Aplica la máscara de variante C0 a cada mitad de 8 bytes de la llave."""
    return bytes(
        b ^ C0_MASK_8[i % 8] for i, b in enumerate(key_bytes)
    )


def crypto_des(key, block):
    """Ejecuta cifrado DES simple utilizando la infraestructura 3DES."""
    cipher = Cipher(TripleDES(key * 3), modes.ECB())
    return cipher.encryptor().update(block)


def crypto_3des_enc(key, block):
    """Ejecuta cifrado Triple DES estándar (Cifrado)."""
    if len(key) == 16:
        key = key + key[:8]
    cipher = Cipher(TripleDES(key), modes.ECB())
    return cipher.encryptor().update(block)


def crypto_3des_dec(key, block):
    """Ejecuta descifrado Triple DES estándar (Descifrado)."""
    if len(key) == 16:
        key = key + key[:8]
    cipher = Cipher(TripleDES(key), modes.ECB())
    return cipher.decryptor().update(block)


def ejecutar_descifrado_dukpt_nativo(bdk_hex, ksn_hex, ciphertext_hex):
    bdk = bytes.fromhex(limpiar_hex(bdk_hex))
    ksn = bytes.fromhex(limpiar_hex(ksn_hex))
    ciphertext = bytes.fromhex(limpiar_hex(ciphertext_hex))

    print("[-] Sincronizando registros DUKPT conforme a la norma ANSI X9.24...")

    # 1. Configurar KSN de 8 bytes para la derivación del IPEK (Primeros 8 bytes del KSN original de 10)
    ksn_base_ipek = bytearray(ksn[:8])
    ksn_base_ipek[7] &= 0xE0  # Limpiar los bits del contador si se traslapan en este byte

    # 2. Derivación del IPEK (Initial PIN Encryption Key)
    ipek_l = crypto_3des_enc(bdk, bytes(ksn_base_ipek))
    bdk_r = aplicar_variante_c0(bdk)  # CORREGIDO: máscara C0 solo en los 4 bytes altos de cada mitad
    ipek_r = crypto_3des_enc(bdk_r, bytes(ksn_base_ipek))
    cur_key = bytearray(ipek_l + ipek_r)

    # 3. Extraer el contador de transacciones real desde los últimos 3 bytes del KSN de 10 bytes (Alineación correcta)
    tc = ((ksn[7] & 0x1F) << 16) | (ksn[8] << 8) | ksn[9]

    # 4. Preparar la base de 8 bytes que DUKPT usará DENTRO del bucle de llaves futuras (Los últimos 8 bytes del KSN)
    ksn_loop_base = bytearray(ksn[2:10])
    ksn_loop_base[5] &= 0xE0
    ksn_loop_base[6] = 0x00
    ksn_loop_base[7] = 0x00

    running_tc = 0
    bit_mask = 0x100000  # Máscara del bit 21 superior del contador DUKPT

    while bit_mask > 0:
        if tc & bit_mask:
            running_tc |= bit_mask

            # Construir el mensaje de 8 bytes exactos para este paso de iteración con los índices corregidos
            msg = bytearray(ksn_loop_base)
            msg[5] |= (running_tc >> 16) & 0x1F
            msg[6] = (running_tc >> 8) & 0xFF
            msg[7] = running_tc & 0xFF

            kl = bytes(cur_key[:8])
            kr = bytes(cur_key[8:16])

            # Proceso de Caja Negra Izquierdo
            c_input_l = bytes(b ^ m for b, m in zip(kr, msg))
            c_output_l = crypto_des(kl, c_input_l)
            nxt_l = bytes(b ^ c for b, c in zip(kr, c_output_l))

            # Proceso de Caja Negra Derecho (variante C0 CORREGIDA en llaves internas)
            kl_m = aplicar_variante_c0(kl)
            kr_m = aplicar_variante_c0(kr)
            c_input_r = bytes(b ^ m for b, m in zip(kr_m, msg))
            c_output_r = crypto_des(kl_m, c_input_r)
            nxt_r = bytes(b ^ c for b, c in zip(kr_m, c_output_r))

            # IMPORTANTE: el orden es (mitad derivada con la variante C0) + (mitad derivada sin variante),
            # es decir nxt_r primero y nxt_l después. Invertir este orden produce un data key
            # con las mitades intercambiadas y por tanto un descifrado corrupto.
            cur_key = bytearray(nxt_r + nxt_l)

        bit_mask >>= 1

    # 5. Máscaras de variante estándar (ANSI X9.24-1, Tabla de variantes de llave).
    #    Cada "propósito" de llave aplica XOR 0xFF en dos bytes distintos de la
    #    Current Key de 16 bytes. No hay forma de saber de antemano cuál se usó
    #    para cifrar el mensaje, así que probamos las 5 + la propia Current Key.
    variantes = {
        "Current Key (sin variante)": (),
        "PIN Encryption Key":          (7, 15),
        "MAC Request Key":             (6, 14),
        "MAC Response Key":            (4, 12),
        "Data Request Key":            (5, 13),
        "Data Response Key":           (3, 11),
    }

    def aplicar_variante(base_key, indices):
        k = bytearray(base_key)
        for i in indices:
            k[i] ^= 0xFF
        return bytes(k)

    resultados = []
    for nombre, indices in variantes.items():
        llave = aplicar_variante(cur_key, indices)
        for modo_nombre, modo in (("ECB", modes.ECB()), ("CBC (IV=0)", modes.CBC(bytes(8)))):
            try:
                clave_tdes = llave + llave[:8] if len(llave) == 16 else llave
                cipher = Cipher(TripleDES(clave_tdes), modo)
                claro = cipher.decryptor().update(ciphertext)
            except Exception:
                continue
            legible = claro.decode('ascii', errors='ignore')
            # Heurística simple: ¿la mayoría de los bytes son ASCII imprimible?
            imprimibles = sum(1 for b in claro if 0x20 <= b <= 0x7E)
            score = imprimibles / max(len(claro), 1)
            resultados.append((nombre, modo_nombre, llave, claro, score))

    # Ordenar de mayor a menor "legibilidad" para mostrar primero los candidatos más probables
    resultados.sort(key=lambda r: r[4], reverse=True)

    print("\n[-] Probando las 6 variantes de llave x 2 modos de cifrado (12 combinaciones)...")
    print("    (ordenadas de más a menos texto ASCII imprimible)\n")
    for nombre, modo_nombre, llave, claro, score in resultados:
        texto = claro.decode('utf-8', errors='ignore').strip()
        marca = "✅" if score > 0.9 else ("〰️" if score > 0.5 else "  ")
        print(f"{marca} {nombre:<28} | {modo_nombre:<10} | key={llave.hex().upper()} | hex={claro.hex().upper()} | txt={texto!r}")

    # Devolvemos el mejor candidato (Data Request Key + ECB) como resultado "por defecto",
    # manteniendo compatibilidad con el resto del script.
    mejor = resultados[0]
    return mejor[2].hex().upper(), mejor[3].hex().upper(), mejor[3].decode('utf-8', errors='ignore').strip()


def main():
    parser = argparse.ArgumentParser(description="Motor Autónomo DUKPT Puro - Corrección de máscara de variante C0")
    parser.add_argument("--bdk", required=True)
    parser.add_argument("--ksn", required=True)
    parser.add_argument("--ciphertext", required=True)

    args = parser.parse_args()

    try:
        d_key, clear_hex, clear_txt = ejecutar_descifrado_dukpt_nativo(args.bdk, args.ksn, args.ciphertext)
        print("\n" + "=" * 70)
        print("          RESULTADO DE LA DECODIFICACIÓN DUKPT (CORREGIDO)")
        print("=" * 70)
        print(f"Data Variant Key:     {d_key}")
        print(f"Mensaje Claro (Hex):  {clear_hex}")
        print(f"Mensaje Claro (TXT):  👉 {clear_txt} 👈")
        print("=" * 70 + "\n")
    except Exception as e:
        print(f"❌ Error: {e}", file=sys.stderr)


if __name__ == "__main__":
    main()