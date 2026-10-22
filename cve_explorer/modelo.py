"""Modelo de datos común.

Cada base de datos devuelve la información con un formato distinto. Aquí se
define un "registro" único para que todas las fuentes queden en las mismas
columnas y se puedan combinar en Excel o Power BI.
"""

from __future__ import annotations

from dataclasses import dataclass, fields
from datetime import date
from typing import Iterable, Optional

# Nombres de las fuentes tal como aparecen en los reportes.
FUENTE_NVD = "NVD"
FUENTE_KEV = "CISA KEV"
FUENTE_GHSA = "GitHub Advisory"
ORDEN_FUENTES = [FUENTE_NVD, FUENTE_KEV, FUENTE_GHSA]

# Severidades normalizadas (de mayor a menor).
SEVERIDADES = ["CRÍTICA", "ALTA", "MEDIA", "BAJA", "NINGUNA", "SIN CALIFICAR"]
# Número para ordenar en Power BI/Excel: CRÍTICA=5 ... SIN CALIFICAR=0
ORDEN_SEVERIDAD = {sev: len(SEVERIDADES) - 1 - i for i, sev in enumerate(SEVERIDADES)}

_MAPA_SEVERIDAD = {
    "CRITICAL": "CRÍTICA",
    "HIGH": "ALTA",
    "MEDIUM": "MEDIA",
    "MODERATE": "MEDIA",  # GitHub usa "moderate"
    "LOW": "BAJA",
    "NONE": "NINGUNA",
}


@dataclass
class Registro:
    """Una vulnerabilidad tal como la reporta UNA fuente."""

    fuente: str
    cve_id: str
    id_fuente: Optional[str] = None          # CVE-ID en NVD/KEV, GHSA-ID en GitHub
    titulo: Optional[str] = None
    descripcion: Optional[str] = None
    fecha_publicacion: Optional[date] = None  # en KEV: fecha en que CISA la agregó
    fecha_actualizacion: Optional[date] = None
    severidad: Optional[str] = None
    cvss_puntaje: Optional[float] = None
    cvss_version: Optional[str] = None
    cvss_vector: Optional[str] = None
    cwe: Optional[str] = None                 # "CWE-79; CWE-89"
    proveedor: Optional[str] = None
    producto: Optional[str] = None
    ecosistema: Optional[str] = None          # npm, pip, Maven... (solo GitHub)
    explotada_activamente: Optional[bool] = None
    ransomware: Optional[str] = None          # solo CISA KEV
    fecha_limite_cisa: Optional[date] = None  # solo CISA KEV
    estado: Optional[str] = None
    url: Optional[str] = None


COLUMNAS_REGISTRO = [f.name for f in fields(Registro)]


def severidad_por_puntaje(puntaje: float) -> str:
    """Rangos oficiales de CVSS v3/v4."""
    p = float(puntaje)
    if p == 0:
        return "NINGUNA"
    if p < 4.0:
        return "BAJA"
    if p < 7.0:
        return "MEDIA"
    if p < 9.0:
        return "ALTA"
    return "CRÍTICA"


def normalizar_severidad(valor: Optional[str], puntaje: Optional[float] = None) -> Optional[str]:
    """Convierte 'HIGH', 'moderate', etc. a la escala en español.

    Si la fuente no trae texto de severidad pero sí puntaje, se calcula.
    """
    if valor:
        sev = _MAPA_SEVERIDAD.get(str(valor).strip().upper())
        if sev:
            return sev
    if puntaje is not None:
        return severidad_por_puntaje(puntaje)
    return None


def unicos(valores: Iterable) -> list:
    """Quita repetidos y vacíos conservando el orden original."""
    vistos, salida = set(), []
    for v in valores:
        if v and v not in vistos:
            vistos.add(v)
            salida.append(v)
    return salida


def fecha_iso(texto: Optional[str]) -> Optional[date]:
    """'2024-01-15T10:30:00.000Z' -> date(2024, 1, 15)."""
    if not texto:
        return None
    try:
        return date.fromisoformat(str(texto)[:10])
    except ValueError:
        return None


def version_de_vector(vector: Optional[str], defecto: Optional[str] = None) -> Optional[str]:
    """'CVSS:3.1/AV:N/...' -> '3.1'."""
    if vector and vector.startswith("CVSS:"):
        return vector.split("/", 1)[0].split(":", 1)[1]
    return defecto


def nombre_proveedor(texto: Optional[str]) -> Optional[str]:
    """'palo_alto_networks' -> 'Palo Alto Networks'; 'ibm' -> 'IBM'."""
    if not texto or texto in ("*", "-"):
        return None
    limpio = texto.replace("_", " ").replace("\\", "").strip()
    if len(limpio) <= 3:
        return limpio.upper()
    return limpio.title() if limpio.islower() else limpio
