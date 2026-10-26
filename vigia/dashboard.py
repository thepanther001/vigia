"""Genera un dashboard web (un solo index.html) a partir de los datos procesados.

* Funciona abriéndolo localmente o publicado en GitHub Pages.
* Los datos van dentro del HTML como JSON (no hace falta servidor).
* Seguridad:
    - Los textos de las CVE vienen de fuentes externas, así que el JSON se escapa
      para que un "</script>" dentro de una descripción no pueda inyectar código (XSS).
    - En el navegador todo se pinta con textContent (nunca innerHTML con datos).
    - Content-Security-Policy con el hash SHA-256 del script: el navegador solo
      ejecuta ESE script y la librería de gráficos (versión fija con
      verificación SRI); nada más.
"""

from __future__ import annotations

import base64
import hashlib
import json
import math
import shutil
from datetime import date, datetime, timezone
from pathlib import Path

import pandas as pd

from vigia import __version__
from vigia import procesamiento as proc
from vigia.prioridad import NIVELES

# Chart.js fijado a una versión exacta + Subresource Integrity (SRI): si el CDN
# entregara un archivo alterado, el navegador se niega a ejecutarlo.
CHART_JS = "https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.js"
CHART_JS_SRI = "sha384-dug+JxfBvklEQdJ4AYuBBAIScUz0bVN73xpy273gcAwHjb3qI0fXmuYNaNfdyYJG"
MAX_CVE_EN_PANEL = 1500


# ----------------------------------------------------------------- datos

def _valor(v):
    """Convierte valores de pandas/numpy a algo que JSON entienda."""
    if v is None:
        return None
    if isinstance(v, float) and math.isnan(v):
        return None
    if isinstance(v, (pd.Timestamp, datetime, date)):
        return None if pd.isna(v) else v.strftime("%Y-%m-%d")
    if hasattr(v, "item"):  # numpy
        v = v.item()
        if isinstance(v, float) and math.isnan(v):
            return None
    if v is pd.NaT or (not isinstance(v, (str, bool, int, float)) and pd.isna(v)):
        return None
    return v


def construir_datos(
    registros: pd.DataFrame,
    consolidado: pd.DataFrame,
    resumenes: dict,
    kpis: dict,
    desde: date,
    hasta: date,
    fuentes: list[str],
    estado_fuentes: dict,
    inventario: dict | None,
    descargas: dict,
) -> dict:
    ordenado = consolidado.sort_values(
        ["prioridad_puntaje", "cvss_puntaje"], ascending=False, na_position="last"
    ).head(MAX_CVE_EN_PANEL)

    def fila_cve(r) -> dict:
        return {
            "id": r.cve_id,
            "titulo": _valor(r.titulo),
            "sev": _valor(r.severidad),
            "cvss": _valor(r.cvss_puntaje),
            "epss": _valor(getattr(r, "epss", None)),
            "pct": _valor(getattr(r, "epss_percentil", None)),
            "kev": bool(r.en_kev),
            "rans": r.ransomware == "Sí",
            "prov": _valor(r.proveedor),
            "prod": _valor(r.producto),
            "eco": _valor(r.ecosistema),
            "fecha": _valor(r.fecha_publicacion),
            "limite": _valor(r.fecha_limite_cisa),
            "fuentes": _valor(r.fuentes),
            "puntaje": _valor(r.prioridad_puntaje),
            "nivel": _valor(r.prioridad_nivel),
            "plazo": _valor(r.prioridad_plazo),
            "motivo": _valor(r.prioridad_motivo),
            "activos": _valor(getattr(r, "activos_afectados", None)),
            "url": _valor(r.url),
        }

    niveles = consolidado["prioridad_nivel"].value_counts()
    return {
        "meta": {
            "generado": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "desde": desde.isoformat(),
            "hasta": hasta.isoformat(),
            "fuentes": fuentes,
            "estado": estado_fuentes,
            "version": __version__,
        },
        "kpis": {
            "total": kpis["CVE únicas"],
            "criticas": kpis["Críticas"],
            "altas": kpis["Altas"],
            "explotadas": kpis["Explotadas activamente"],
            "ransomware": kpis["Usadas en ransomware"],
            "inmediata": int(niveles.get("INMEDIATA", 0)),
            "urgente": int(niveles.get("URGENTE", 0)),
            "cvss_prom": kpis["CVSS promedio"],
        },
        "serie": proc.serie_temporal(registros, desde, hasta),
        "severidad": {r.Severidad: int(r.Cantidad) for r in resumenes["por_severidad"].itertuples()},
        "niveles": [{"nivel": n, "plazo": p, "cve": int(niveles.get(n, 0))} for _, n, p in NIVELES],
        "proveedores": [
            {"nombre": r.Proveedor, "cve": int(r.CVE), "criticas": int(r.Críticas), "explotadas": int(r.Explotadas)}
            for r in resumenes["top_proveedores"].head(10).itertuples()
        ],
        "cwe": [
            {"cwe": r.CWE, "nombre": r.Debilidad, "cve": int(r.CVE)}
            for r in resumenes["top_cwe"].head(10).itertuples()
        ],
        "inventario": inventario,
        "cves": [fila_cve(r) for r in ordenado.itertuples(index=False)],
        "total_cves": int(len(consolidado)),
        "descargas": descargas,
    }


def resumen_inventario(nombre: str, por_activo: pd.DataFrame, afectaciones: pd.DataFrame) -> dict:
    return {
        "nombre": nombre,
        "activos": [
            {
                "activo": r.activo,
                "producto": f"{r.proveedor} {r.producto}".strip(),
                "criticidad": r.criticidad_activo,
                "cve": int(r.CVE),
                "explotadas": int(r.explotadas),
                "prioridad_max": _valor(r.prioridad_max),
            }
            for r in por_activo.itertuples(index=False)
        ],
        "total_afectados": int((por_activo["CVE"] > 0).sum()) if len(por_activo) else 0,
        "total_cve": int(afectaciones["cve_id"].nunique()) if len(afectaciones) else 0,
    }


# ----------------------------------------------------------------- HTML

def _json_seguro(datos: dict) -> str:
    """JSON que no puede cerrar la etiqueta <script> ni abrir comentarios HTML."""
    texto = json.dumps(datos, ensure_ascii=False, separators=(",", ":"))
    return texto.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")


def _hash_csp(script: str) -> str:
    digest = hashlib.sha256(script.encode("utf-8")).digest()
    return "sha256-" + base64.b64encode(digest).decode()


PLANTILLAS = Path(__file__).parent / "plantillas"


def _logo_inline() -> str:
    """Logo en SVG dentro del HTML. El texto 'Vigía' toma el color del tema
    (azul marino en modo claro, blanco en modo oscuro)."""
    svg = (PLANTILLAS / "logo.svg").read_text(encoding="utf-8")
    svg = svg.replace('fill="#1B2B48"', 'style="fill:var(--wordmark)"')
    return svg.replace("<svg ", '<svg aria-hidden="true" focusable="false" ', 1).replace('role="img" ', "")


def _data_uri(nombre: str, tipo: str) -> str:
    contenido = (PLANTILLAS / nombre).read_bytes()
    return f"data:{tipo};base64,{base64.b64encode(contenido).decode()}"


def generar_html(datos: dict) -> str:
    plantilla = (PLANTILLAS / "dashboard.html").read_text(encoding="utf-8")
    script = (PLANTILLAS / "dashboard.js").read_text(encoding="utf-8")
    csp = (
        "default-src 'none'; "
        f"script-src '{_hash_csp(script)}' https://cdn.jsdelivr.net; "
        "style-src 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src https://fonts.gstatic.com; "
        "img-src data:; base-uri 'none'; form-action 'none'"
    )
    return (
        plantilla.replace("__CSP__", csp)
        .replace("__LOGO__", _logo_inline())
        .replace("__FAVICON__", _data_uri("icono.svg", "image/svg+xml"))
        .replace("__ICONO180__", _data_uri("icono-180.png", "image/png"))
        .replace("__CHARTJS__", CHART_JS)
        .replace("__SRI__", CHART_JS_SRI)
        .replace("__SCRIPT__", script)          # primero el script...
        .replace("__DATOS__", _json_seguro(datos))  # ...y al final los datos externos
    )


def generar(carpeta: str | Path, datos: dict, archivos_exportados: list[Path]) -> Path:
    """Escribe index.html y copia el Excel/CSV para que se puedan descargar desde el panel."""
    carpeta = Path(carpeta)
    carpeta.mkdir(parents=True, exist_ok=True)
    descargas = {"excel": None, "csv": []}
    for ruta in archivos_exportados:
        ruta = Path(ruta)
        if ruta.suffix == ".xlsx":
            destino = carpeta / "reporte_cve.xlsx"
            if ruta.resolve() != destino.resolve():
                shutil.copyfile(ruta, destino)
            descargas["excel"] = destino.name
        elif ruta.suffix == ".csv":
            (carpeta / "powerbi").mkdir(exist_ok=True)
            destino = carpeta / "powerbi" / ruta.name
            if ruta.resolve() != destino.resolve():
                shutil.copyfile(ruta, destino)
            descargas["csv"].append(f"powerbi/{ruta.name}")
    datos = {**datos, "descargas": descargas}
    (carpeta / ".nojekyll").write_text("", encoding="utf-8")  # GitHub Pages: servir tal cual
    ruta_html = carpeta / "index.html"
    ruta_html.write_text(generar_html(datos), encoding="utf-8")
    return ruta_html
