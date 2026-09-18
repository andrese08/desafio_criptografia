# V2 — Motor DUKPT y módulo TR-31 (interactiva)

Misma funcionalidad que la V1 (descifrado DUKPT e intercambio de llaves
TR-31), pero con una interfaz de consola interactiva: el programa pregunta
los datos uno por uno, en vez de recibirlos como argumentos.

## Archivos

| Archivo | Descripción |
|---|---|
| `dukpt_interactivo.py` | Descifrado DUKPT, por consola. |
| `key_exchange_interactivo.py` | Exportación de PEK e importación de BDK, por consola. |

## Requisitos

- Python 3.9+
- [`cryptography`](https://pypi.org/project/cryptography/)
- [`psec`](https://pypi.org/project/psec/) (solo para importar una BDK)

```bash
pip install cryptography psec
```

## Uso

### Descifrado DUKPT

```bash
python dukpt_interactivo.py
```

El programa solicita, en orden, el BDK (16 bytes), el KSN (10 bytes) y el
criptograma a descifrar. Valida el formato y la longitud de cada valor, y
vuelve a preguntar si algo no es correcto, sin necesidad de reiniciar el
programa.

### Intercambio de llaves TR-31

```bash
python key_exchange_interactivo.py
```

Primero muestra un menú:

```
¿Qué proceso deseas ejecutar?
  1) Exportar PEK
  2) Importar BDK
```

Luego pide los dos componentes de la KEK y su KCV esperado (comunes a
ambos procesos), y a continuación solo los campos adicionales del proceso
elegido:

- **Exportar PEK**: la ruta del archivo de salida.
- **Importar BDK**: el key block TR-31 de la BDK y su KCV esperado.

Los dos componentes de la KEK se piden con **entrada oculta** (no se
muestran en pantalla mientras se escriben) — el resto de los campos, al no
ser secretos de conocimiento dividido, se piden de forma visible.

## Conceptos clave

Los mismos que en V1 — ver `README_V1.md` para el detalle de KEK, KCV y
DUKPT. Esta versión no cambia ningún concepto ni algoritmo: solo cambia
cómo se ingresan los datos.

## Limitaciones conocidas

- Sigue siendo una herramienta de un solo operador en una sola sesión de
  terminal: no separa el ingreso de cada componente de la KEK entre dos
  personas distintas (doble custodia). Para ese flujo, ver la aplicación
  web (V3).
- No hay registro de auditoría de quién ejecutó el programa ni cuándo.

