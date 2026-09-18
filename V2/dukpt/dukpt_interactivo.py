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
    bdk_r = aplicar_variante_c0(bdk)
    ipek_r = crypto_3des_enc(bdk_r, bytes(ksn_base_ipek))
    cur_key = bytearray(ipek_l + ipek_r)

    # 3. Extraer el contador de transacciones real desde los últimos 3 bytes del KSN de 10 bytes
    tc = ((ksn[7] & 0x1F) << 16) | (ksn[8] << 8) | ksn[9]

    # 4. Preparar la base de 8 bytes que DUKPT usará DENTRO del bucle de llaves futuras
    ksn_loop_base = bytearray(ksn[2:10])
    ksn_loop_base[5] &= 0xE0
    ksn_loop_base[6] = 0x00
    ksn_loop_base[7] = 0x00

    running_tc = 0
    bit_mask = 0x100000  # Máscara del bit 21 superior del contador DUKPT

    while bit_mask > 0:
        if tc & bit_mask:
            running_tc |= bit_mask

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

            # Proceso de Caja Negra Derecho (variante C0)
            kl_m = aplicar_variante_c0(kl)
            kr_m = aplicar_variante_c0(kr)
            c_input_r = bytes(b ^ m for b, m in zip(kr_m, msg))
            c_output_r = crypto_des(kl_m, c_input_r)
            nxt_r = bytes(b ^ c for b, c in zip(kr_m, c_output_r))

            cur_key = bytearray(nxt_r + nxt_l)

        bit_mask >>= 1

    # 5. Máscaras de variante estándar (ANSI X9.24-1, Tabla de variantes de llave).
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
            imprimibles = sum(1 for b in claro if 0x20 <= b <= 0x7E)
            score = imprimibles / max(len(claro), 1)
            resultados.append((nombre, modo_nombre, llave, claro, score))

    resultados.sort(key=lambda r: r[4], reverse=True)

    print("\n[-] Probando las 6 variantes de llave x 2 modos de cifrado (12 combinaciones)...")
    print("    (ordenadas de más a menos texto ASCII imprimible)\n")
    for nombre, modo_nombre, llave, claro, score in resultados:
        texto = claro.decode('utf-8', errors='ignore').strip()
        marca = "✅" if score > 0.9 else ("〰️" if score > 0.5 else "  ")
        print(f"{marca} {nombre:<28} | {modo_nombre:<10} | key={llave.hex().upper()} | hex={claro.hex().upper()} | txt={texto!r}")

    mejor = resultados[0]
    return mejor[2].hex().upper(), mejor[3].hex().upper(), mejor[3].decode('utf-8', errors='ignore').strip()


# ---------------------------------------------------------------------------
# Entrada interactiva por consola
# ---------------------------------------------------------------------------

def pedir_hex(etiqueta, longitud_bytes_esperada=None):
    """
    Pide un valor hexadecimal por consola, reintentando hasta que sea válido.
    Si se indica longitud_bytes_esperada, también valida el tamaño exacto.
    """
    while True:
        valor = input(f"{etiqueta}: ").strip()
        limpio = limpiar_hex(valor)
        if not limpio:
            print("  ⚠ El valor no puede estar vacío. Intenta de nuevo.")
            continue
        try:
            datos = bytes.fromhex(limpio)
        except ValueError:
            print("  ⚠ Eso no es un hexadecimal válido (¿número impar de caracteres, o letras fuera de A-F?). Intenta de nuevo.")
            continue
        if longitud_bytes_esperada is not None and len(datos) != longitud_bytes_esperada:
            print(f"  ⚠ Se esperaban {longitud_bytes_esperada} bytes ({longitud_bytes_esperada * 2} caracteres hex) "
                  f"y se recibieron {len(datos)}. Intenta de nuevo.")
            continue
        return valor


def main():
    print("=" * 70)
    print("   MOTOR DE DESCIFRADO DUKPT (ANSI X9.24) - MODO INTERACTIVO")
    print("=" * 70)
    print("Ingresa los siguientes valores en formato hexadecimal.")
    print("(puedes pegarlos con o sin espacios; ambos formatos se aceptan)\n")

    bdk_hex = pedir_hex("BDK (16 bytes, 32 caracteres hex)", longitud_bytes_esperada=16)
    ksn_hex = pedir_hex("KSN (10 bytes, 20 caracteres hex)", longitud_bytes_esperada=10)
    ciphertext_hex = pedir_hex("Criptograma a descifrar (múltiplo de 8 bytes)")

    try:
        d_key, clear_hex, clear_txt = ejecutar_descifrado_dukpt_nativo(bdk_hex, ksn_hex, ciphertext_hex)
        print("\n" + "=" * 70)
        print("          RESULTADO DE LA DECODIFICACIÓN DUKPT")
        print("=" * 70)
        print(f"Data Variant Key:     {d_key}")
        print(f"Mensaje Claro (Hex):  {clear_hex}")
        print(f"Mensaje Claro (TXT):  👉 {clear_txt} 👈")
        print("=" * 70 + "\n")
    except Exception as e:
        print(f"❌ Error: {e}", file=sys.stderr)


if __name__ == "__main__":
    main()
