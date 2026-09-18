# V3 — Motor DUKPT y módulo TR-31 (aplicación web)

Interfaz web para las mismas dos operaciones de las versiones anteriores
(descifrado DUKPT e intercambio de llaves TR-31), con un flujo adicional de
**doble custodia**: los dos componentes de la KEK pueden ser ingresados por
dos personas distintas, cada una desde un enlace independiente, sin que
ninguna vea el componente de la otra.

Se ejecuta como contenedor Docker.

## Cómo ejecutar

```bash
docker-compose up -d
```

o, sin `docker compose`:

```bash
docker build -t key-exchange-web .
docker run -p 5000:5000 key-exchange-web
```

Luego abre `http://localhost:5000`.

## Funcionalidad

| Página | Qué hace |
|---|---|
| Descifrado DUKPT | Mismo formulario y resultado que en V1/V2, con descarga del reporte. |
| Exportar PEK | Genera una PEK y la entrega en un key block TR-31. |
| Importar BDK | Desenvuelve y valida un key block TR-31 de una BDK. |

Para "Exportar PEK" e "Importar BDK", el operador elige entre dos modos:

- **Persona única**: se ingresan todos los datos en una sola pantalla,
  igual que en V1/V2.
- **Con custodios**: el sistema genera dos enlaces temporales de un solo
  uso. Cada custodio ingresa su componente de la KEK desde su propio
  enlace; el operador solo ve el estado (pendiente/recibido) y una vista
  parcial de cada componente (los últimos 4 caracteres, para confirmar
  recepción sin exponerlo). El botón para ejecutar el proceso permanece
  deshabilitado hasta que ambos custodios hayan enviado su parte.

En ambos modos, el resultado se muestra en pantalla y se puede descargar
como archivo de texto.

## Arquitectura

```
app.py              # Rutas Flask, sesiones de custodios, descargas
crypto_core.py      # Núcleo criptográfico (DUKPT + TR-31)
templates/          # Vistas HTML
static/             # CSS y JavaScript
Dockerfile
docker-compose.yml
requirements.txt
```

## Requisitos (fuera de Docker)

- Python 3.9+
- Flask, cryptography, psec, gunicorn — ver `requirements.txt`.

## Seguridad

Esta versión incluye varias medidas orientadas a un uso en red:

- Los componentes de la KEK nunca se muestran completos en pantalla ni se
  registran en ningún log — solo se exponen los últimos 4 caracteres.
- Rate limiting por IP y por ruta.
- Cabeceras de seguridad HTTP (incluyendo una Content-Security-Policy
  estricta).
- Validación de origen en los formularios.
- El contenedor ejecuta la aplicación con un usuario sin privilegios de
  administrador.

**Antes de usarla en producción**, ten en cuenta:

- El estado (sesiones de custodios, archivos de resultado) vive en memoria
  del proceso — se pierde si el contenedor se reinicia, y no está pensado
  para escalar a múltiples réplicas sin migrar ese estado a un almacén
  compartido.
- No incluye autenticación de usuarios: cualquiera con acceso a la URL
  puede operar la aplicación. Debe desplegarse detrás de una red o un
  mecanismo de autenticación propios de tu organización.
- Debe servirse bajo HTTPS (por ejemplo, mediante un proxy inverso) — el
  contenedor por sí solo sirve HTTP plano.

