function copiarEnlace(elementId) {
  const el = document.getElementById(elementId);
  if (!el) return;
  navigator.clipboard.writeText(el.textContent.trim()).then(() => {
    const btn = document.getElementById("btn-" + elementId);
    if (btn) {
      const original = btn.textContent;
      btn.textContent = "¡Copiado!";
      setTimeout(() => { btn.textContent = original; }, 1500);
    }
  });
}

function iniciarPollingCustodios(estadoUrl) {
  const badge1 = document.getElementById("badge-1");
  const badge2 = document.getElementById("badge-2");
  const mask1 = document.getElementById("mask-1");
  const mask2 = document.getElementById("mask-2");
  const btnEjecutar = document.getElementById("btn-ejecutar");

  async function actualizar() {
    try {
      const resp = await fetch(estadoUrl);
      if (!resp.ok) return;
      const data = await resp.json();

      if (data.submitted_1) {
        badge1.textContent = "Recibido";
        badge1.className = "badge badge-listo";
        mask1.textContent = data.mask_1;
      } else {
        badge1.textContent = "Pendiente";
        badge1.className = "badge badge-pendiente";
      }

      if (data.submitted_2) {
        badge2.textContent = "Recibido";
        badge2.className = "badge badge-listo";
        mask2.textContent = data.mask_2;
      } else {
        badge2.textContent = "Pendiente";
        badge2.className = "badge badge-pendiente";
      }

      if (btnEjecutar) {
        btnEjecutar.disabled = !(data.submitted_1 && data.submitted_2);
      }
    } catch (e) {
      // silencioso: se reintenta en el próximo ciclo
    }
  }

  actualizar();
  setInterval(actualizar, 3000);
}

// ---------------------------------------------------------------------------
// Auto-inicialización basada en atributos data-*, en vez de onclick="..." o
// <script> inline en las plantillas — así la Content-Security-Policy puede
// exigir script-src 'self' SIN 'unsafe-inline', que es la protección real
// que una CSP aporta contra inyección de scripts (XSS).
// ---------------------------------------------------------------------------
document.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll("[data-copy-target]").forEach((btn) => {
    btn.addEventListener("click", () => copiarEnlace(btn.getAttribute("data-copy-target")));
  });

  const contenedorEstado = document.querySelector("[data-estado-url]");
  if (contenedorEstado) {
    iniciarPollingCustodios(contenedorEstado.getAttribute("data-estado-url"));
  }
});
