"""Cruce de vulnerabilidades con el inventario de software de una organización.

Responde la pregunta "de todas estas CVE, ¿cuáles me afectan a MÍ?".
El inventario es un CSV sencillo (ver inventario/empresa_ejemplo.csv):

    activo,proveedor,producto,version,criticidad
    Servidor de correo,Microsoft,Exchange Server,2019 CU14,Alta

La coincidencia es por proveedor + producto (no por versión): es un primer
filtro para que el analista revise. La versión exacta se confirma a mano
contra el aviso del fabricante.
"""

from __future__ import annotations

import csv
import re
from dataclasses import dataclass
from pathlib import Path

import pandas as pd

CRITICIDADES = {"alta": 3, "media": 2, "baja": 1}
_PALABRAS_VACIAS = {"the", "for", "and", "de", "del", "la", "el"}


@dataclass(frozen=True)
class Activo:
    activo: str
    proveedor: str
    producto: str
    version: str = ""
    criticidad: str = "Media"


class InventarioError(ValueError):
    pass


def cargar(ruta: str | Path) -> list[Activo]:
    ruta = Path(ruta)
    if not ruta.exists():
        raise InventarioError(f"No existe el inventario: {ruta}")
    with ruta.open(encoding="utf-8-sig", newline="") as f:
        lector = csv.DictReader(f)
        faltan = {"activo", "proveedor", "producto"} - set(lector.fieldnames or [])
        if faltan:
            raise InventarioError(f"Al inventario le faltan columnas: {', '.join(sorted(faltan))}")
        activos = []
        for fila in lector:
            if not (fila.get("producto") or "").strip():
                continue
            criticidad = (fila.get("criticidad") or "Media").strip().capitalize()
            activos.append(Activo(
                activo=(fila.get("activo") or "").strip(),
                proveedor=(fila.get("proveedor") or "").strip(),
                producto=fila["producto"].strip(),
                version=(fila.get("version") or "").strip(),
                criticidad=criticidad if criticidad.lower() in CRITICIDADES else "Media",
            ))
    return activos


def _compacto(texto: str) -> str:
    """'Palo Alto Networks' y 'paloaltonetworks' -> 'paloaltonetworks'."""
    return re.sub(r"[^a-z0-9]", "", str(texto).lower())


def _palabras(texto: str) -> set[str]:
    """Palabras significativas, sin números de versión: 'Windows Server 2019' -> {windows, server}."""
    palabras = set(re.findall(r"[a-z0-9]+", str(texto).lower().replace("_", " ")))
    return {p for p in palabras if not p.isdigit() and p not in _PALABRAS_VACIAS}


def mismo_proveedor(a: str, b: str) -> bool:
    ca, cb = _compacto(a), _compacto(b)
    return bool(ca and cb) and (ca in cb or cb in ca)


def mismo_producto(inventario: str, reportado: str) -> bool:
    pi, pr = _palabras(inventario), _palabras(reportado)
    return bool(pi and pr) and (pi <= pr or pr <= pi)


def coincide(activo: Activo, proveedor, productos) -> bool:
    if not isinstance(productos, str) or not productos:
        return False
    if activo.proveedor:
        if not isinstance(proveedor, str) or not mismo_proveedor(activo.proveedor, proveedor):
            return False
    return any(mismo_producto(activo.producto, p) for p in productos.split(", "))


def cruzar(consolidado: pd.DataFrame, activos: list[Activo]) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Devuelve (consolidado con columna 'activos_afectados', tabla de afectaciones)."""
    df = consolidado.copy()
    filas = []
    afectados_por_cve: dict[str, list[str]] = {}
    for registro in df.itertuples(index=False):
        for activo in activos:
            if coincide(activo, registro.proveedor, registro.producto):
                afectados_por_cve.setdefault(registro.cve_id, []).append(activo.activo)
                filas.append({
                    "activo": activo.activo,
                    "criticidad_activo": activo.criticidad,
                    "version_instalada": activo.version,
                    "cve_id": registro.cve_id,
                    "titulo": registro.titulo,
                    "severidad": registro.severidad,
                    "cvss_puntaje": registro.cvss_puntaje,
                    "prioridad_puntaje": getattr(registro, "prioridad_puntaje", None),
                    "prioridad_nivel": getattr(registro, "prioridad_nivel", None),
                    "explotada_activamente": registro.explotada_activamente,
                    "fecha_publicacion": registro.fecha_publicacion,
                    "url": registro.url,
                })
    df["activos_afectados"] = df["cve_id"].map(lambda c: ", ".join(afectados_por_cve.get(c, [])) or None)

    afectaciones = pd.DataFrame(filas, columns=[
        "activo", "criticidad_activo", "version_instalada", "cve_id", "titulo", "severidad",
        "cvss_puntaje", "prioridad_puntaje", "prioridad_nivel", "explotada_activamente",
        "fecha_publicacion", "url",
    ])
    if not afectaciones.empty:
        afectaciones["_c"] = afectaciones["criticidad_activo"].str.lower().map(CRITICIDADES).fillna(2)
        afectaciones = afectaciones.sort_values(
            ["prioridad_puntaje", "_c", "cvss_puntaje"], ascending=False, na_position="last"
        ).drop(columns="_c").reset_index(drop=True)
    return df, afectaciones


def resumen_por_activo(afectaciones: pd.DataFrame, activos: list[Activo]) -> pd.DataFrame:
    """Una fila por activo del inventario (incluye los que no tienen CVE)."""
    base = pd.DataFrame([{"activo": a.activo, "proveedor": a.proveedor, "producto": a.producto,
                          "criticidad_activo": a.criticidad} for a in activos])
    if base.empty:
        return base
    if afectaciones.empty:
        base["CVE"] = 0
        base["explotadas"] = 0
        base["prioridad_max"] = None
    else:
        g = afectaciones.groupby("activo")
        base = base.merge(pd.DataFrame({
            "CVE": g["cve_id"].nunique(),
            "explotadas": g["explotada_activamente"].sum().astype(int),
            "prioridad_max": g["prioridad_puntaje"].max(),
        }), left_on="activo", right_index=True, how="left")
        base[["CVE", "explotadas"]] = base[["CVE", "explotadas"]].fillna(0).astype(int)
    return base.sort_values(["prioridad_max", "CVE"], ascending=False, na_position="last").reset_index(drop=True)
