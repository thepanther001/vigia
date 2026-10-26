"""Índice de prioridad de parcheo (0 a 100).

El CVSS solo dice qué tan GRAVE es una vulnerabilidad, no qué tan PROBABLE es
que la usen contra ti. Este índice combina cuatro señales para responder la
pregunta que importa en un equipo de seguridad: ¿qué parcho primero?

    Puntaje = 4 × CVSS                       (gravedad,          máx. 40)
            + 25 × percentil EPSS            (probabilidad,      máx. 25)
            + 25 si está en CISA KEV         (ya la explotan,        25)
            + 10 si se usa en ransomware     (impacto conocido,      10)
                                                                  ─────
                                                                    100
Reglas mínimas (pisos):
    * Si está en KEV, nunca baja de 60  -> ya la están usando en ataques reales.
    * Si se usa en ransomware, nunca baja de 80.
    * Si el CVSS es 9.0 o más, nunca baja de 40.

Idea basada en la práctica real: CISA BOD 22-01 (parchar lo explotado primero),
FIRST EPSS y el modelo SSVC. La fórmula es propia y se puede ajustar abajo.
"""

from __future__ import annotations

import math

import pandas as pd

PESO_CVSS = 4.0
PESO_EPSS = 25.0
PUNTOS_KEV = 25.0
PUNTOS_RANSOMWARE = 10.0
PISO_KEV = 60.0
PISO_RANSOMWARE = 80.0
PISO_CVSS_CRITICO = 40.0

# (puntaje mínimo, nivel, plazo recomendado)
NIVELES = [
    (80, "INMEDIATA", "24–48 horas"),
    (60, "URGENTE", "7 días"),
    (40, "PLANIFICADA", "30 días"),
    (0, "RUTINA", "Próximo ciclo de parches"),
]
ORDEN_NIVEL = {nivel: len(NIVELES) - i for i, (_, nivel, _) in enumerate(NIVELES)}


def _num(valor) -> float | None:
    try:
        v = float(valor)
    except (TypeError, ValueError):
        return None
    return None if math.isnan(v) else v


def nivel_de(puntaje: float) -> tuple[str, str]:
    for minimo, nivel, plazo in NIVELES:
        if puntaje >= minimo:
            return nivel, plazo
    return NIVELES[-1][1], NIVELES[-1][2]


def calcular(cvss=None, epss_percentil=None, en_kev=False, ransomware=False) -> tuple[float, list[str]]:
    """Devuelve (puntaje, lista de motivos legibles)."""
    cvss = _num(cvss)
    pct = _num(epss_percentil)
    puntos = 0.0
    motivos: list[str] = []

    if en_kev:
        puntos += PUNTOS_KEV
        motivos.append("Explotada activamente (CISA KEV)")
    if ransomware:
        puntos += PUNTOS_RANSOMWARE
        motivos.append("Usada en ransomware")
    if cvss is not None:
        puntos += PESO_CVSS * cvss
        motivos.append(f"CVSS {cvss:.1f}")
    else:
        motivos.append("Sin CVSS")
    if pct is not None:
        puntos += PESO_EPSS * pct
        if pct >= 0.5:
            motivos.append(f"EPSS: más probable que el {pct * 100:.0f}% de las CVE")

    if en_kev:
        puntos = max(puntos, PISO_KEV)
    if ransomware:
        puntos = max(puntos, PISO_RANSOMWARE)
    if cvss is not None and cvss >= 9.0:
        puntos = max(puntos, PISO_CVSS_CRITICO)

    return round(min(puntos, 100.0), 1), motivos


def agregar_prioridad(consolidado: pd.DataFrame) -> pd.DataFrame:
    """Agrega las columnas prioridad_puntaje, prioridad_nivel, prioridad_plazo y prioridad_motivo."""
    df = consolidado.copy()
    if df.empty:
        for col in ("prioridad_puntaje", "prioridad_nivel", "prioridad_plazo", "prioridad_motivo"):
            df[col] = pd.Series(dtype=object)
        return df

    tiene_epss = "epss_percentil" in df.columns
    resultados = [
        calcular(
            fila.cvss_puntaje,
            getattr(fila, "epss_percentil", None) if tiene_epss else None,
            bool(fila.en_kev),
            fila.ransomware == "Sí",
        )
        for fila in df.itertuples(index=False)
    ]
    df["prioridad_puntaje"] = [p for p, _ in resultados]
    niveles = [nivel_de(p) for p, _ in resultados]
    df["prioridad_nivel"] = [n for n, _ in niveles]
    df["prioridad_plazo"] = [pl for _, pl in niveles]
    df["prioridad_motivo"] = [" · ".join(m) for _, m in resultados]
    return df


def top_prioridad(consolidado: pd.DataFrame, n: int = 50) -> pd.DataFrame:
    if consolidado.empty or "prioridad_puntaje" not in consolidado.columns:
        return consolidado.head(0)
    return consolidado.sort_values(
        ["prioridad_puntaje", "cvss_puntaje", "fecha_publicacion"], ascending=False, na_position="last"
    ).head(n).reset_index(drop=True)


def resumen_niveles(consolidado: pd.DataFrame) -> pd.DataFrame:
    nombres = [nivel for _, nivel, _ in NIVELES]
    plazos = [plazo for _, _, plazo in NIVELES]
    conteo = (consolidado["prioridad_nivel"].value_counts() if len(consolidado) else pd.Series(dtype=int))
    return pd.DataFrame({
        "Nivel": nombres,
        "Plazo recomendado": plazos,
        "CVE": [int(conteo.get(n, 0)) for n in nombres],
    })
