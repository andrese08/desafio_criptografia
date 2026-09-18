import io
import os
import secrets
import threading
import time
import uuid
from functools import wraps
from urllib.parse import urlparse

from flask import Flask, render_template, request, redirect, url_for, jsonify, send_file, abort

import crypto_core as cc

app = Flask(__name__)


@app.after_request
def _agregar_cabeceras_seguridad(response):
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "same-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "frame-ancestors 'none'"
    )
    return response


def _mismo_origen(origen_header, host_esperado):
    if not origen_header or origen_header == "null":
        return False
    try:
        return urlparse(origen_header).netloc.lower() == host_esperado.lower()
    except ValueError:
        return False


def exigir_mismo_origen(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if request.method == "POST":
            origen = request.headers.get("Origin") or request.headers.get("Referer")
            if not _mismo_origen(origen, request.host):
                abort(403, description="Solicitud rechazada: origen no verificado.")
        return f(*args, **kwargs)
    return wrapper


class _RateLimiter:
    def __init__(self):
        self._lock = threading.Lock()
        self._hits = {}

    def permitir(self, clave, max_solicitudes, ventana_segundos):
        ahora = time.time()
        corte = ahora - ventana_segundos
        with self._lock:
            marcas = [t for t in self._hits.get(clave, []) if t >= corte]
            if len(marcas) >= max_solicitudes:
                self._hits[clave] = marcas
                return False
            marcas.append(ahora)
            self._hits[clave] = marcas
            return True

    def purgar_vacios(self):
        with self._lock:
            for clave in list(self._hits.keys()):
                if not self._hits[clave]:
                    del self._hits[clave]


_RATE_LIMITER = _RateLimiter()


def limitar_tasa(max_solicitudes, ventana_segundos):
    """Decorador: máx. `max_solicitudes` por IP y por ruta cada `ventana_segundos`."""
    def decorador(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            ip_cliente = request.headers.get("X-Forwarded-For", request.remote_addr) or "desconocido"
            clave = f"{request.endpoint}:{ip_cliente.split(',')[0].strip()}"
            if not _RATE_LIMITER.permitir(clave, max_solicitudes, ventana_segundos):
                abort(429, description="Demasiadas solicitudes. Intenta de nuevo en unos segundos.")
            return f(*args, **kwargs)
        return wrapper
    return decorador


# ---------------------------------------------------------------------------
# Almacenamiento en memoria (ver advertencia arriba)
# ---------------------------------------------------------------------------

_LOCK = threading.Lock()
CUSTODIAN_SESSIONS = {}   # session_id -> dict
RESULT_FILES = {}         # result_id -> {"filename": str, "content": bytes, "created_at": float}

SESSION_TTL_SECONDS = 30 * 60      # 30 minutos para que los custodios ingresen sus componentes
RESULT_FILE_TTL_SECONDS = 60 * 60  # 1 hora para descargar el resultado


def _purgar_expirados():
    """Elimina sesiones de custodios y archivos de resultado vencidos."""
    ahora = time.time()
    with _LOCK:
        for sid in list(CUSTODIAN_SESSIONS.keys()):
            if CUSTODIAN_SESSIONS[sid]["expires_at"] < ahora:
                del CUSTODIAN_SESSIONS[sid]
        for rid in list(RESULT_FILES.keys()):
            if RESULT_FILES[rid]["created_at"] + RESULT_FILE_TTL_SECONDS < ahora:
                del RESULT_FILES[rid]
    _RATE_LIMITER.purgar_vacios()


def _nueva_sesion_custodios(process):
    """Crea una nueva sesión de doble custodia para el proceso indicado."""
    session_id = uuid.uuid4().hex
    now = time.time()
    sesion = {
        "process": process,                       # "export-pek" | "import-bdk"
        "created_at": now,
        "expires_at": now + SESSION_TTL_SECONDS,
        "tokens": {"1": secrets.token_urlsafe(24), "2": secrets.token_urlsafe(24)},
        "consumed_tokens": set(),
        "components": {"1": None, "2": None},      # valores completos, SOLO en memoria de servidor
        "masks": {"1": None, "2": None},           # lo único que se expone a la vista
        "submitted_at": {"1": None, "2": None},
    }
    with _LOCK:
        CUSTODIAN_SESSIONS[session_id] = sesion
    return session_id, sesion


def _obtener_sesion(session_id):
    _purgar_expirados()
    with _LOCK:
        sesion = CUSTODIAN_SESSIONS.get(session_id)
    if sesion is None:
        abort(404, description="La sesión no existe o ya expiró.")
    return sesion


def _token_a_sesion(token):
    """Busca a qué sesión y a qué número de custodio (1 o 2) pertenece un token."""
    _purgar_expirados()
    with _LOCK:
        for sid, sesion in CUSTODIAN_SESSIONS.items():
            for num, tok in sesion["tokens"].items():
                if tok == token:
                    return sid, sesion, num
    return None, None, None


def _guardar_resultado(filename, texto):
    result_id = uuid.uuid4().hex
    with _LOCK:
        RESULT_FILES[result_id] = {
            "filename": filename,
            "content": texto.encode("utf-8"),
            "created_at": time.time(),
        }
    return result_id


# ---------------------------------------------------------------------------
# Menú principal
# ---------------------------------------------------------------------------

@app.route("/")
@limitar_tasa(60, 60)
def menu():
    return render_template("menu.html")


# ---------------------------------------------------------------------------
# DUKPT
# ---------------------------------------------------------------------------

@app.route("/dukpt", methods=["GET", "POST"])
@limitar_tasa(30, 60)
@exigir_mismo_origen
def dukpt():
    resultado = None
    error = None
    download_id = None
    valores = {"bdk": "", "ksn": "", "ciphertext": ""}

    if request.method == "POST":
        valores["bdk"] = request.form.get("bdk", "")
        valores["ksn"] = request.form.get("ksn", "")
        valores["ciphertext"] = request.form.get("ciphertext", "")
        try:
            resultado = cc.ejecutar_descifrado_dukpt(valores["bdk"], valores["ksn"], valores["ciphertext"])
            texto = _formatear_reporte_dukpt(resultado)
            download_id = _guardar_resultado("resultado_dukpt.txt", texto)
        except cc.ErrorValidacion as e:
            error = str(e)
        except Exception as e:
            error = f"Error inesperado al descifrar: {e}"

    return render_template("dukpt.html", resultado=resultado, error=error,
                            download_id=download_id, valores=valores)


def _formatear_reporte_dukpt(resultado):
    lineas = ["RESULTADO DE LA DECODIFICACIÓN DUKPT", "=" * 70]
    for c in resultado["candidatos"]:
        marca = "OK" if c["score"] > 0.9 else ("~" if c["score"] > 0.5 else "  ")
        lineas.append(
            f"[{marca}] {c['nombre']:<28} | {c['modo']:<10} | key={c['llave']} | hex={c['hex']} | txt={c['texto']!r}"
        )
    return "\n".join(lineas)


# ---------------------------------------------------------------------------
# Selección de modo (persona única / custodios) — común a export-pek e import-bdk
# ---------------------------------------------------------------------------

_PROCESOS = {
    "export-pek": {
        "titulo": "Exportar PEK",
        "explicacion": (
            "Genera una PEK (PIN Encryption Key) TDES aleatoria y la entrega "
            "envuelta en un key block TR-31 Versión D, protegida bajo la KEK "
            "acordada con la contraparte."
        ),
        "entrega": "Un key block TR-31 con la PEK, más su KCV para que la contraparte lo verifique.",
    },
    "import-bdk": {
        "titulo": "Importar BDK",
        "explicacion": (
            "Desenvuelve un key block TR-31 que contiene una BDK (Base "
            "Derivation Key) protegida bajo la KEK acordada con la "
            "contraparte, y valida su integridad contra el KCV esperado."
        ),
        "entrega": "La BDK en claro (hex) y la confirmación de que su KCV coincide con el esperado.",
    },
}


@app.route("/<proceso>/modo")
@limitar_tasa(60, 60)
def elegir_modo(proceso):
    if proceso not in _PROCESOS:
        abort(404)
    return render_template("modo.html", proceso=proceso, info=_PROCESOS[proceso])


# ---------------------------------------------------------------------------
# Flujo "una sola persona"
# ---------------------------------------------------------------------------

@app.route("/export-pek/individual", methods=["GET", "POST"])
@limitar_tasa(30, 60)
@exigir_mismo_origen
def export_pek_individual():
    error = None
    resultado = None
    download_id = None
    valores = {"kek_component_1": "", "kek_component_2": "", "kek_kcv": ""}

    if request.method == "POST":
        valores["kek_component_1"] = request.form.get("kek_component_1", "")
        valores["kek_component_2"] = request.form.get("kek_component_2", "")
        valores["kek_kcv"] = request.form.get("kek_kcv", "")
        try:
            kek_bytes = cc.recombinar_y_validar_kek(
                valores["kek_component_1"], valores["kek_component_2"], valores["kek_kcv"]
            )
            resultado = cc.generar_pek_keyblock(kek_bytes)
            texto = _formatear_reporte_pek(resultado)
            download_id = _guardar_resultado("pek_keyblock.txt", texto)
        except cc.ErrorValidacion as e:
            error = str(e)
        except Exception as e:
            error = f"Error inesperado: {e}"

    return render_template("individual_export.html", error=error, resultado=resultado,
                            download_id=download_id, valores=valores)


@app.route("/import-bdk/individual", methods=["GET", "POST"])
@limitar_tasa(30, 60)
@exigir_mismo_origen
def import_bdk_individual():
    error = None
    resultado = None
    download_id = None
    valores = {"kek_component_1": "", "kek_component_2": "", "kek_kcv": "",
               "bdk_keyblock": "", "bdk_kcv": ""}

    if request.method == "POST":
        for campo in valores:
            valores[campo] = request.form.get(campo, "")
        try:
            kek_bytes = cc.recombinar_y_validar_kek(
                valores["kek_component_1"], valores["kek_component_2"], valores["kek_kcv"]
            )
            resultado = cc.importar_bdk_keyblock(kek_bytes, valores["bdk_keyblock"], valores["bdk_kcv"])
            texto = _formatear_reporte_bdk(resultado)
            download_id = _guardar_resultado("bdk_importada.txt", texto)
        except cc.ErrorValidacion as e:
            error = str(e)
        except Exception as e:
            error = f"Error inesperado: {e}"

    return render_template("individual_import.html", error=error, resultado=resultado,
                            download_id=download_id, valores=valores)


def _formatear_reporte_pek(r):
    return (
        "PROCESAMIENTO DE EXPORTACIÓN PEK\n" + "=" * 70 + "\n"
        f"Criptograma TR-31:  {r['block_hex']}\n"
        f"KCV de la PEK TDES: {r['kcv_pek']}\n"
        + ("Autoverificación: OK\n" if r["autoverificacion_ok"] else "Autoverificación: FALLIDA\n")
    )


def _formatear_reporte_bdk(r):
    return (
        "PROCESAMIENTO DE IMPORTACIÓN BDK\n" + "=" * 70 + "\n"
        f"Encabezado TR-31:   {r['header']}\n"
        f"BDK en claro (hex): {r['bdk_hex']}\n"
        f"KCV calculado:      {r['kcv_calculado']}\n"
        f"KCV esperado:       {r['kcv_esperado']}\n"
        + ("Validación: EXITOSA\n" if r["validacion_exitosa"] else "Validación: FALLIDA\n")
    )


# ---------------------------------------------------------------------------
# Flujo "custodios" — página principal del operador
# ---------------------------------------------------------------------------

@app.route("/<proceso>/custodios/nueva", methods=["POST"])
@limitar_tasa(10, 60)
@exigir_mismo_origen
def custodios_nueva(proceso):
    if proceso not in _PROCESOS:
        abort(404)
    session_id, _ = _nueva_sesion_custodios(proceso)
    return redirect(url_for("custodios_operador", proceso=proceso, session_id=session_id))


@app.route("/<proceso>/custodios/<session_id>")
@limitar_tasa(60, 60)
def custodios_operador(proceso, session_id):
    if proceso not in _PROCESOS:
        abort(404)
    sesion = _obtener_sesion(session_id)
    if sesion["process"] != proceso:
        abort(404)

    enlace_1 = url_for("custodio_entrada", token=sesion["tokens"]["1"], _external=True)
    enlace_2 = url_for("custodio_entrada", token=sesion["tokens"]["2"], _external=True)

    template = "custodios_export.html" if proceso == "export-pek" else "custodios_import.html"
    return render_template(
        template,
        proceso=proceso,
        session_id=session_id,
        enlace_1=enlace_1,
        enlace_2=enlace_2,
    )


@app.route("/<proceso>/custodios/<session_id>/estado")
@limitar_tasa(60, 60)
def custodios_estado(proceso, session_id):
    sesion = _obtener_sesion(session_id)
    return jsonify({
        "submitted_1": sesion["submitted_at"]["1"] is not None,
        "submitted_2": sesion["submitted_at"]["2"] is not None,
        "mask_1": sesion["masks"]["1"] or "",
        "mask_2": sesion["masks"]["2"] or "",
    })


@app.route("/<proceso>/custodios/<session_id>/ejecutar", methods=["POST"])
@limitar_tasa(15, 60)
@exigir_mismo_origen
def custodios_ejecutar(proceso, session_id):
    sesion = _obtener_sesion(session_id)
    if sesion["process"] != proceso:
        abort(404)

    error = None
    resultado = None
    download_id = None

    kek_kcv = request.form.get("kek_kcv", "")

    if sesion["submitted_at"]["1"] is None or sesion["submitted_at"]["2"] is None:
        error = "Aún falta que uno o ambos custodios ingresen su componente."
    else:
        try:
            with _LOCK:
                comp1 = sesion["components"]["1"]
                comp2 = sesion["components"]["2"]
            kek_bytes = cc.recombinar_y_validar_kek(comp1, comp2, kek_kcv)

            if proceso == "export-pek":
                resultado = cc.generar_pek_keyblock(kek_bytes)
                texto = _formatear_reporte_pek(resultado)
                download_id = _guardar_resultado("pek_keyblock.txt", texto)
            else:
                bdk_keyblock = request.form.get("bdk_keyblock", "")
                bdk_kcv = request.form.get("bdk_kcv", "")
                resultado = cc.importar_bdk_keyblock(kek_bytes, bdk_keyblock, bdk_kcv)
                texto = _formatear_reporte_bdk(resultado)
                download_id = _guardar_resultado("bdk_importada.txt", texto)
        except cc.ErrorValidacion as e:
            error = str(e)
        except Exception as e:
            error = f"Error inesperado: {e}"

    enlace_1 = url_for("custodio_entrada", token=sesion["tokens"]["1"], _external=True)
    enlace_2 = url_for("custodio_entrada", token=sesion["tokens"]["2"], _external=True)
    template = "custodios_export.html" if proceso == "export-pek" else "custodios_import.html"
    return render_template(
        template,
        proceso=proceso,
        session_id=session_id,
        enlace_1=enlace_1,
        enlace_2=enlace_2,
        error=error,
        resultado=resultado,
        download_id=download_id,
        kek_kcv_valor=kek_kcv,
        bdk_keyblock_valor=request.form.get("bdk_keyblock", ""),
        bdk_kcv_valor=request.form.get("bdk_kcv", ""),
    )


# ---------------------------------------------------------------------------
# Página temporal para custodios (enlace compartible, un solo uso)
# ---------------------------------------------------------------------------

@app.route("/custodio/<token>", methods=["GET", "POST"])
@limitar_tasa(20, 60)
@exigir_mismo_origen
def custodio_entrada(token):
    session_id, sesion, numero = _token_a_sesion(token)
    if sesion is None:
        return render_template("custodio_invalido.html"), 404

    with _LOCK:
        ya_usado = token in sesion["consumed_tokens"]
        mask_preview = sesion["masks"][numero]
    enviado = False
    error = None

    if request.method == "POST" and not ya_usado:
        componente = request.form.get("componente", "")
        limpio = cc.limpiar_hex(componente)
        try:
            valor_bytes = bytes.fromhex(limpio)
        except ValueError:
            error = "Ese valor no es hexadecimal válido."
            valor_bytes = None
        if valor_bytes is not None and len(valor_bytes) != 32:
            error = f"Se esperaban 32 bytes (64 caracteres hex) y se recibieron {len(valor_bytes)}."
            valor_bytes = None

        if valor_bytes is not None:
            # Sección crítica: check-and-set ATÓMICO dentro del mismo lock,
            # para cerrar la condición de carrera (TOCTOU) entre dos envíos
            # concurrentes al mismo token. Solo el primero que entra aquí
            # consume el token; si un segundo hilo llega después (incluso
            # una fracción de segundo), encuentra el token ya consumido y
            # no sobrescribe el componente ya guardado.
            with _LOCK:
                if token in sesion["consumed_tokens"]:
                    ya_usado = True
                else:
                    sesion["components"][numero] = limpio
                    sesion["masks"][numero] = cc.mask_value(limpio)
                    sesion["submitted_at"][numero] = time.time()
                    sesion["consumed_tokens"].add(token)
                    enviado = True
                    ya_usado = True
                    mask_preview = sesion["masks"][numero]

    proceso_info = _PROCESOS.get(sesion["process"], {"titulo": sesion["process"]})

    return render_template(
        "custodio_entrada.html",
        numero=numero,
        proceso_titulo=proceso_info["titulo"],
        ya_usado=ya_usado,
        enviado=enviado,
        error=error,
        mask_preview=mask_preview,
    )


# ---------------------------------------------------------------------------
# Descarga de resultados
# ---------------------------------------------------------------------------

@app.route("/descargar/<result_id>")
@limitar_tasa(30, 60)
def descargar(result_id):
    _purgar_expirados()
    with _LOCK:
        entry = RESULT_FILES.get(result_id)
    if entry is None:
        abort(404, description="El archivo ya no está disponible (expiró o ya fue descargado).")
    return send_file(
        io.BytesIO(entry["content"]),
        as_attachment=True,
        download_name=entry["filename"],
        mimetype="text/plain",
    )


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
