# V1 — Motor DUKPT y módulo TR-31 (línea de comandos)

Herramientas de línea de comandos para dos operaciones comunes en el manejo
de llaves de pagos electrónicos:

- **Descifrado DUKPT** (ANSI X9.24): reconstruye la llave de una transacción
  específica a partir de la BDK (Base Derivation Key) y el KSN (Key Serial
  Number), y descifra un criptograma con ella.
- **Intercambio de llaves TR-31** (ANSI X9.143): reconstruye una KEK (Key
  Encryption Key) a partir de sus dos componentes, y con ella exporta una
  PEK (PIN Encryption Key) o importa una BDK, ambas protegidas en un key
  block TR-31 Versión D.

Ambos scripts se ejecutan de forma independiente, sin necesidad de instalar
el proyecto como paquete.

## Archivos

| Archivo | Descripción |
|---|---|
| `decrypt_pure.py` | Descifrado DUKPT. |
| `key_exchange.py` | Exportación de PEK e importación de BDK bajo TR-31. |

## Requisitos

- Python 3.9+
- [`cryptography`](https://pypi.org/project/cryptography/)
- [`psec`](https://pypi.org/project/psec/) (solo para `import-bdk`)

```bash
pip install cryptography psec
```

## Uso

### Descifrado DUKPT

```bash
python decrypt_pure.py \
  --bdk <BDK en hexadecimal, 16 bytes> \
  --ksn <KSN en hexadecimal, 10 bytes> \
  --ciphertext <criptograma en hexadecimal>
```

Ejemplo:
```bash
python decrypt_pure.py \
  --bdk 0123456789ABCDEFFEDCBA9876543210 \
  --ksn FFFF9876543210E00001 \
  --ciphertext D0911CD510047AC6AEE9CE8AFEDA9301
```

El programa prueba las 6 variantes de llave de trabajo (PIN, MAC Request,
MAC Response, Data Request, Data Response, y la Current Key sin variante)
en 2 modos de cifrado cada una, y muestra las 12 combinaciones ordenadas
por qué tanto el resultado parece texto legible.

### Exportar una PEK

```bash
python key_exchange.py export-pek \
  --kek-component-1 <componente 1 de la KEK> \
  --kek-component-2 <componente 2 de la KEK> \
  --kek-kcv <KCV esperado de la KEK> \
  --out pek_block.txt
```

Genera una PEK aleatoria, la envuelve en un key block TR-31 Versión D bajo
la KEK reconstruida, y se autoverifica (desenvuelve su propio resultado)
antes de guardarlo en el archivo indicado.

### Importar una BDK

```bash
python key_exchange.py import-bdk \
  --kek-component-1 <componente 1 de la KEK> \
  --kek-component-2 <componente 2 de la KEK> \
  --kek-kcv <KCV esperado de la KEK> \
  --bdk-keyblock <key block TR-31 de la BDK> \
  --bdk-kcv <KCV esperado de la BDK>
```

Desenvuelve el key block recibido y valida su KCV contra el esperado.

## Conceptos clave

- **KEK (Key Encryption Key)**: llave que protege a las demás llaves en
  tránsito. Se reconstruye combinando dos componentes con XOR — ninguno de
  los dos, por separado, revela nada sobre la KEK resultante (conocimiento
  dividido / *split knowledge*).
- **KCV (Key Check Value)**: huella de 3 bytes de una llave, usada para
  confirmar que dos partes tienen la misma llave sin transmitirla.
- **DUKPT**: mecanismo que deriva una llave distinta por cada transacción a
  partir de una raíz (BDK) y un contador público (KSN), sin sincronización
  en tiempo real entre terminal y procesador.

## Limitaciones conocidas

- Los datos se reciben como argumentos de línea de comandos, por lo que
  quedan visibles en el historial del shell y en la lista de procesos del
  sistema mientras el comando se ejecuta. No recomendado para llaves de
  producción — ver la versión interactiva (V2) o la aplicación web (V3).
- No hay registro de auditoría de quién ejecutó cada comando.
