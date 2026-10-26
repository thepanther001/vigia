"""Limpieza, consolidación y tablas resumen con pandas.

Se generan dos vistas:
  * registros   -> una fila por CVE y por fuente (permite comparar fuentes)
  * consolidado -> una fila por CVE, combinando lo mejor de cada fuente
"""

from __future__ import annotations

from dataclasses import asdict
from datetime import date
from typing import Iterable

import pandas as pd

from vigia.modelo import (
    COLUMNAS_REGISTRO,
    FUENTE_GHSA,
    FUENTE_KEV,
    FUENTE_NVD,
    ORDEN_FUENTES,
    ORDEN_SEVERIDAD,
    SEVERIDADES,
    Registro,
)

# Qué fuente "manda" para cada grupo de columnas al consolidar.
PRIORIDAD_DATOS = [FUENTE_NVD, FUENTE_GHSA, FUENTE_KEV]      # descripción y CVSS
PRIORIDAD_TITULO = [FUENTE_KEV, FUENTE_GHSA, FUENTE_NVD]     # nombre corto
PRIORIDAD_PRODUCTO = [FUENTE_KEV, FUENTE_NVD, FUENTE_GHSA]   # proveedor/producto

COLUMNAS_CONSOLIDADO = [
    "cve_id", "titulo", "severidad", "severidad_orden", "cvss_puntaje", "cvss_version",
    "fecha_publicacion", "anio", "mes", "proveedor", "producto", "ecosistema", "cwe",
    "explotada_activamente", "ransomware", "fecha_limite_cisa",
    "en_nvd", "en_kev", "en_github", "num_fuentes", "fuentes",
    "cvss_vector", "estado", "descripcion", "url",
]

COLUMNAS_FECHA = ["fecha_publicacion", "fecha_actualizacion", "fecha_limite_cisa"]

NOMBRES_CWE = {
    "CWE-20": "Validación de entrada incorrecta",
    "CWE-22": "Path traversal",
    "CWE-74": "Inyección (neutralización incorrecta)",
    "CWE-77": "Inyección de comandos",
    "CWE-78": "Inyección de comandos del sistema operativo",
    "CWE-79": "Cross-site scripting (XSS)",
    "CWE-89": "Inyección SQL",
    "CWE-94": "Inyección de código",
    "CWE-119": "Desbordamiento de búfer de memoria",
    "CWE-121": "Desbordamiento de pila (stack)",
    "CWE-122": "Desbordamiento de heap",
    "CWE-125": "Lectura fuera de límites",
    "CWE-190": "Desbordamiento de enteros",
    "CWE-200": "Exposición de información sensible",
    "CWE-209": "Mensajes de error con información sensible",
    "CWE-269": "Gestión incorrecta de privilegios",
    "CWE-276": "Permisos por defecto incorrectos",
    "CWE-284": "Control de acceso incorrecto",
    "CWE-287": "Autenticación incorrecta",
    "CWE-306": "Falta de autenticación en función crítica",
    "CWE-352": "Cross-site request forgery (CSRF)",
    "CWE-362": "Condición de carrera",
    "CWE-400": "Consumo de recursos no controlado (DoS)",
    "CWE-401": "Fuga de memoria",
    "CWE-416": "Uso después de liberar",
    "CWE-427": "Ruta de búsqueda no controlada",
    "CWE-434": "Carga de archivos peligrosos sin restricción",
    "CWE-476": "Desreferencia de puntero NULL",
    "CWE-502": "Deserialización de datos no confiables",
    "CWE-601": "Redirección abierta",
    "CWE-611": "XML External Entity (XXE)",
    "CWE-639": "IDOR (referencia insegura)",
    "CWE-668": "Exposición de recurso a esfera incorrecta",
    "CWE-732": "Asignación incorrecta de permisos",
    "CWE-770": "Asignación de recursos sin límites",
    "CWE-787": "Escritura fuera de límites",
    "CWE-798": "Credenciales embebidas en el código",
    "CWE-862": "Falta de autorización",
    "CWE-863": "Autorización incorrecta",
    "CWE-918": "Server-side request forgery (SSRF)",
    "CWE-1321": "Prototype pollution",
}


def registros_a_df(registros: Iterable[Registro]) -> pd.DataFrame:
    df = pd.DataFrame([asdict(r) for r in registros], columns=COLUMNAS_REGISTRO)
    texto = [c for c in COLUMNAS_REGISTRO if c not in COLUMNAS_FECHA + ["cvss_puntaje", "explotada_activamente"]]
    df[texto] = df[texto].astype(object).where(df[texto].notna() & (df[texto] != ""), None)
    for col in COLUMNAS_FECHA:
        df[col] = pd.to_datetime(df[col], errors="coerce")
    df["cvss_puntaje"] = pd.to_numeric(df["cvss_puntaje"], errors="coerce")
    df["explotada_activamente"] = df["explotada_activamente"].map(lambda v: v is True)
    df = df.dropna(subset=["cve_id"]).drop_duplicates(subset=["fuente", "id_fuente"])
    return df.reset_index(drop=True)


def _primero_por_prioridad(df: pd.DataFrame, columnas: list[str], prioridad: list[str]) -> pd.DataFrame:
    """Para cada CVE toma el primer valor no vacío siguiendo el orden de fuentes indicado."""
    orden = {fuente: i for i, fuente in enumerate(prioridad)}
    ordenado = df.assign(_prioridad=df["fuente"].map(orden)).sort_values(["cve_id", "_prioridad"])
    return ordenado.groupby("cve_id")[columnas].first()


def consolidar(df: pd.DataFrame) -> pd.DataFrame:
    """Une las filas de todas las fuentes en una sola fila por CVE."""
    if df.empty:
        return pd.DataFrame(columns=COLUMNAS_CONSOLIDADO)

    grupos = df.groupby("cve_id")
    presencia = pd.crosstab(df["cve_id"], df["fuente"]).gt(0)
    for fuente in ORDEN_FUENTES:
        if fuente not in presencia.columns:
            presencia[fuente] = False

    salida = pd.DataFrame(index=presencia.index)
    salida["en_nvd"] = presencia[FUENTE_NVD]
    salida["en_kev"] = presencia[FUENTE_KEV]
    salida["en_github"] = presencia[FUENTE_GHSA]
    salida["num_fuentes"] = presencia[ORDEN_FUENTES].sum(axis=1).astype(int)
    salida["fuentes"] = presencia[ORDEN_FUENTES].apply(
        lambda fila: ", ".join(f for f in ORDEN_FUENTES if fila[f]), axis=1
    )

    salida = salida.join(
        _primero_por_prioridad(
            df, ["descripcion", "severidad", "cvss_puntaje", "cvss_version", "cvss_vector", "estado"],
            PRIORIDAD_DATOS,
        )
    )
    salida = salida.join(_primero_por_prioridad(df, ["titulo"], PRIORIDAD_TITULO))
    salida = salida.join(_primero_por_prioridad(df, ["url"], PRIORIDAD_DATOS))
    salida = salida.join(_primero_por_prioridad(df, ["proveedor", "producto", "ecosistema"], PRIORIDAD_PRODUCTO))
    salida["fecha_publicacion"] = grupos["fecha_publicacion"].min()
    salida["explotada_activamente"] = grupos["explotada_activamente"].any()

    kev = df[df["fuente"] == FUENTE_KEV].groupby("cve_id")[["ransomware", "fecha_limite_cisa"]].first()
    salida = salida.join(kev)

    # Unión de todas las CWE reportadas por cualquier fuente.
    cwe = df[["cve_id", "cwe"]].dropna()
    if not cwe.empty:
        cwe = cwe.assign(cwe=cwe["cwe"].str.split("; ")).explode("cwe")
        salida["cwe"] = cwe.groupby("cve_id")["cwe"].agg(lambda s: "; ".join(sorted(set(s))))
    else:
        salida["cwe"] = None

    # Si ninguna fuente trae título, se usa el inicio de la descripción.
    sin_titulo = salida["titulo"].isna() & salida["descripcion"].notna()
    salida.loc[sin_titulo, "titulo"] = salida.loc[sin_titulo, "descripcion"].map(_resumir)

    salida["severidad"] = salida["severidad"].fillna("SIN CALIFICAR")
    salida["severidad_orden"] = salida["severidad"].map(ORDEN_SEVERIDAD).astype(int)
    salida["anio"] = salida["fecha_publicacion"].dt.year.astype("Int64")
    salida["mes"] = salida["fecha_publicacion"].dt.strftime("%Y-%m")

    salida = salida.reset_index().rename(columns={"index": "cve_id"})
    salida = salida.sort_values(["fecha_publicacion", "cvss_puntaje"], ascending=[False, False], na_position="last")
    return salida[COLUMNAS_CONSOLIDADO].reset_index(drop=True)


def _resumir(texto: str, largo: int = 110) -> str:
    texto = " ".join(str(texto).split())
    return texto if len(texto) <= largo else texto[: largo - 1].rstrip() + "…"


def agregar_epss(consolidado: pd.DataFrame, puntajes: dict[str, tuple[float, float]]) -> pd.DataFrame:
    df = consolidado.copy()
    df["epss"] = df["cve_id"].map(lambda c: puntajes.get(c, (None, None))[0])
    df["epss_percentil"] = df["cve_id"].map(lambda c: puntajes.get(c, (None, None))[1])
    return df


# ----------------------------------------------------------------- tablas resumen

def tabla_por_mes(registros: pd.DataFrame, consolidado: pd.DataFrame, desde: date, hasta: date,
                  fuentes: list[str] | None = None) -> pd.DataFrame:
    """Cantidad de CVE por mes y por fuente (incluye los meses sin datos, en 0)."""
    fuentes = [f for f in ORDEN_FUENTES if f in (fuentes or ORDEN_FUENTES)]
    meses = pd.period_range(desde, hasta, freq="M").strftime("%Y-%m")
    tabla = pd.DataFrame(index=pd.Index(meses, name="Mes"), columns=fuentes, data=0)
    if not registros.empty:
        tmp = registros.dropna(subset=["fecha_publicacion"])
        tmp = tmp.assign(Mes=tmp["fecha_publicacion"].dt.strftime("%Y-%m"))
        pivote = tmp.pivot_table(index="Mes", columns="fuente", values="cve_id", aggfunc="nunique")
        tabla.update(pivote.reindex(index=tabla.index, columns=fuentes))
    tabla = tabla.fillna(0).astype(int)
    unicas = consolidado.groupby("mes")["cve_id"].nunique() if not consolidado.empty else pd.Series(dtype=int)
    tabla["CVE únicas"] = unicas.reindex(tabla.index).fillna(0).astype(int)
    return tabla.reset_index()


def tabla_por_severidad(consolidado: pd.DataFrame) -> pd.DataFrame:
    conteo = consolidado["severidad"].value_counts().reindex(SEVERIDADES, fill_value=0)
    total = int(conteo.sum())
    return pd.DataFrame({
        "Severidad": conteo.index,
        "Cantidad": conteo.values.astype(int),
        "Porcentaje": (conteo.values / total) if total else 0.0,
    })


def tabla_top_proveedores(consolidado: pd.DataFrame, n: int = 15) -> pd.DataFrame:
    datos = consolidado.dropna(subset=["proveedor"])
    if datos.empty:
        return pd.DataFrame(columns=["Proveedor", "CVE", "Críticas", "Explotadas"])
    datos = datos.assign(_clave=datos["proveedor"].str.strip().str.lower())
    tabla = datos.groupby("_clave").agg(
        Proveedor=("proveedor", lambda s: s.mode().iat[0]),
        CVE=("cve_id", "nunique"),
        Críticas=("severidad", lambda s: int((s == "CRÍTICA").sum())),
        Explotadas=("explotada_activamente", "sum"),
    )
    tabla["Explotadas"] = tabla["Explotadas"].astype(int)
    return tabla.sort_values(["CVE", "Críticas"], ascending=False).head(n).reset_index(drop=True)


def tabla_cwe_por_cve(consolidado: pd.DataFrame) -> pd.DataFrame:
    """Tabla 'larga' (una fila por CVE y CWE). Útil para relacionar en Power BI."""
    datos = consolidado[["cve_id", "cwe"]].dropna()
    if datos.empty:
        return pd.DataFrame(columns=["cve_id", "cwe", "nombre_cwe"])
    datos = datos.assign(cwe=datos["cwe"].str.split("; ")).explode("cwe")
    datos["nombre_cwe"] = datos["cwe"].map(NOMBRES_CWE).fillna("")
    return datos.reset_index(drop=True)


def tabla_top_cwe(consolidado: pd.DataFrame, n: int = 15) -> pd.DataFrame:
    largo = tabla_cwe_por_cve(consolidado)
    if largo.empty:
        return pd.DataFrame(columns=["CWE", "Debilidad", "CVE"])
    conteo = largo["cwe"].value_counts().head(n)
    return pd.DataFrame({
        "CWE": conteo.index,
        "Debilidad": [NOMBRES_CWE.get(c, "") for c in conteo.index],
        "CVE": conteo.values.astype(int),
    })


def indicadores(consolidado: pd.DataFrame, registros: pd.DataFrame) -> dict:
    sev = consolidado["severidad"].value_counts()
    return {
        "CVE únicas": int(len(consolidado)),
        "Críticas": int(sev.get("CRÍTICA", 0)),
        "Altas": int(sev.get("ALTA", 0)),
        "Explotadas activamente": int(consolidado["explotada_activamente"].sum()) if len(consolidado) else 0,
        "Usadas en ransomware": int((consolidado["ransomware"] == "Sí").sum()) if len(consolidado) else 0,
        "CVSS promedio": round(float(consolidado["cvss_puntaje"].mean()), 2)
        if consolidado["cvss_puntaje"].notna().any() else None,
        "Registros por fuente": registros["fuente"].value_counts().to_dict(),
    }


def completar_desde_nvd(consolidado: pd.DataFrame, extra: pd.DataFrame) -> pd.DataFrame:
    """Rellena CVSS/severidad/CWE de filas que no los tienen, usando registros extra de la NVD.

    Solo completa datos vacíos: no cambia fechas, fuentes ni conteos.
    """
    if consolidado.empty or extra.empty:
        return consolidado
    df = consolidado.set_index("cve_id")
    nvd = extra.drop_duplicates("cve_id").set_index("cve_id")
    comunes = df.index.intersection(nvd.index)
    sin_cvss = df.loc[comunes, "cvss_puntaje"].isna()
    objetivo = sin_cvss[sin_cvss].index
    for col in ("cvss_puntaje", "cvss_version", "cvss_vector"):
        df.loc[objetivo, col] = nvd.loc[objetivo, col]
    nueva_sev = nvd.loc[objetivo, "severidad"].fillna("SIN CALIFICAR")
    df.loc[objetivo, "severidad"] = nueva_sev
    df.loc[objetivo, "severidad_orden"] = nueva_sev.map(ORDEN_SEVERIDAD).astype(int)
    sin_cwe = df.loc[comunes, "cwe"].isna()
    df.loc[sin_cwe[sin_cwe].index, "cwe"] = nvd.loc[sin_cwe[sin_cwe].index, "cwe"]
    return df.reset_index()


def serie_temporal(registros: pd.DataFrame, desde: date, hasta: date) -> dict:
    """Diaria si el rango es corto (<= 92 días); mensual si es largo."""
    diaria = (hasta - desde).days <= 92
    if diaria:
        etiquetas = pd.date_range(desde, hasta, freq="D").strftime("%Y-%m-%d").tolist()
        formato = "%Y-%m-%d"
    else:
        etiquetas = pd.period_range(desde, hasta, freq="M").strftime("%Y-%m").tolist()
        formato = "%Y-%m"
    series = {}
    datos = registros.dropna(subset=["fecha_publicacion"])
    for fuente in ORDEN_FUENTES:
        sub = datos[datos["fuente"] == fuente]
        if sub.empty and fuente not in set(registros["fuente"]):
            continue
        conteo = sub.groupby(sub["fecha_publicacion"].dt.strftime(formato))["cve_id"].nunique()
        series[fuente] = [int(conteo.get(e, 0)) for e in etiquetas]
    return {"granularidad": "día" if diaria else "mes", "etiquetas": etiquetas, "series": series}
