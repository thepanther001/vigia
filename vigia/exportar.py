"""Exportación a Excel (con formato, tablas y gráficos) y a CSV (para Power BI)."""

from __future__ import annotations

import re
from datetime import date, datetime
from pathlib import Path

import pandas as pd
from openpyxl.cell.cell import ILLEGAL_CHARACTERS_RE
from openpyxl.chart import BarChart, LineChart, Reference
from openpyxl.chart.axis import ChartLines
from openpyxl.chart.shapes import GraphicalProperties
from openpyxl.drawing.line import LineProperties
from openpyxl.chart.label import DataLabelList
from openpyxl.chart.series import DataPoint
from openpyxl.formatting.rule import CellIsRule
from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
from openpyxl.utils import get_column_letter
from openpyxl.worksheet.table import Table, TableStyleInfo

from vigia import __version__
from vigia.procesamiento import serie_temporal

# Paleta del reporte
AZUL = "1B2B48"
AZUL_CLARO = "E8EEF7"
GRIS = "6B7280"
COLOR_NIVEL = {
    "INMEDIATA": "C0392B",
    "URGENTE": "E67E22",
    "PLANIFICADA": "F1C40F",
    "RUTINA": "BDC3C7",
}
COLOR_SEVERIDAD = {
    "CRÍTICA": "C0392B",
    "ALTA": "E67E22",
    "MEDIA": "F1C40F",
    "BAJA": "27AE60",
    "NINGUNA": "95A5A6",
    "SIN CALIFICAR": "BDC3C7",
}

ANCHOS = {
    "cve_id": 17, "fuente": 15, "id_fuente": 21, "titulo": 50, "descripcion": 90,
    "severidad": 14, "severidad_orden": 9, "cvss_puntaje": 9, "cvss_version": 9,
    "cvss_vector": 46, "fecha_publicacion": 13, "fecha_actualizacion": 13,
    "fecha_limite_cisa": 13, "anio": 7, "mes": 9, "proveedor": 22, "producto": 28,
    "ecosistema": 14, "cwe": 22, "explotada_activamente": 11, "ransomware": 12,
    "en_nvd": 8, "en_kev": 8, "en_github": 9, "num_fuentes": 9, "fuentes": 32,
    "estado": 24, "url": 45, "epss": 9, "epss_percentil": 10,
    "prioridad_puntaje": 10, "prioridad_nivel": 14, "prioridad_plazo": 16, "prioridad_motivo": 60,
    "activos_afectados": 30, "activo": 28, "criticidad_activo": 11, "version_instalada": 14,
    "explotadas": 11, "prioridad_max": 12,
}
ENCABEZADOS = {
    "cve_id": "CVE", "fuente": "Fuente", "id_fuente": "ID en la fuente", "titulo": "Título",
    "descripcion": "Descripción", "severidad": "Severidad", "severidad_orden": "Orden sev.",
    "cvss_puntaje": "CVSS", "cvss_version": "Versión CVSS", "cvss_vector": "Vector CVSS",
    "fecha_publicacion": "Publicada", "fecha_actualizacion": "Actualizada",
    "fecha_limite_cisa": "Límite CISA", "anio": "Año", "mes": "Mes", "proveedor": "Proveedor",
    "producto": "Producto", "ecosistema": "Ecosistema", "cwe": "CWE",
    "explotada_activamente": "Explotada", "ransomware": "Ransomware", "en_nvd": "En NVD",
    "en_kev": "En KEV", "en_github": "En GitHub", "num_fuentes": "Nº fuentes",
    "fuentes": "Fuentes", "estado": "Estado / acción", "url": "Enlace", "epss": "EPSS",
    "epss_percentil": "Percentil EPSS", "prioridad_puntaje": "Prioridad (0-100)",
    "prioridad_nivel": "Nivel", "prioridad_plazo": "Corregir en", "prioridad_motivo": "Motivo",
    "activos_afectados": "Activos afectados", "activo": "Activo", "criticidad_activo": "Criticidad",
    "version_instalada": "Versión instalada", "explotadas": "Explotadas", "prioridad_max": "Prioridad máx.",
}
COLUMNAS_PRIORIDAD = [
    "prioridad_puntaje", "prioridad_nivel", "prioridad_plazo", "cve_id", "titulo", "severidad",
    "cvss_puntaje", "epss", "epss_percentil", "explotada_activamente", "ransomware", "fecha_limite_cisa",
    "proveedor", "producto", "activos_afectados", "prioridad_motivo", "fecha_publicacion", "url",
]
COLUMNAS_BOOL = ["explotada_activamente", "en_nvd", "en_kev", "en_github"]
PELIGROSOS = ("=", "+", "-", "@", "\t", "\r")
# Caracteres que XML 1.0 no permite y que openpyxl no filtra (U+FFFE, U+FFFF y
# sustitutos sueltos). Si se cuelan, Excel dice que el archivo está dañado.
NO_VALIDOS_XML = re.compile("[\ufffe\uffff\ud800-\udfff]")


# ----------------------------------------------------------------- limpieza

def _texto_seguro(valor, maximo: int = 32000):
    """Quita caracteres de control y evita la 'inyección de fórmulas' (CSV/Formula injection).

    Un texto que empieza con =, +, -, @ podría ejecutarse como fórmula al abrirse
    en Excel. Por eso se le antepone un espacio.
    """
    if not isinstance(valor, str):
        return valor
    valor = ILLEGAL_CHARACTERS_RE.sub("", valor)
    valor = NO_VALIDOS_XML.sub("", valor)
    if valor.startswith(PELIGROSOS):
        valor = " " + valor
    return valor[:maximo]


def limpiar(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    for col in df.columns:
        if df[col].dtype == object:
            df[col] = df[col].map(_texto_seguro)
    return df


def _nombre_base(desde: date, hasta: date) -> str:
    return f"cve_{desde:%Y%m%d}_{hasta:%Y%m%d}_{datetime.now():%Y%m%d-%H%M%S}"


# ----------------------------------------------------------------- CSV

def exportar_csv(tablas: dict[str, pd.DataFrame], carpeta: Path) -> list[Path]:
    """Guarda cada tabla como CSV UTF-8 (con BOM, para que Excel lea bien las tildes).

    La carpeta 'powerbi' se sobrescribe en cada corrida: así Power BI siempre
    apunta a la misma ruta y basta con darle a 'Actualizar'.
    """
    carpeta.mkdir(parents=True, exist_ok=True)
    rutas = []
    for nombre, df in tablas.items():
        ruta = carpeta / f"{nombre}.csv"
        salida = limpiar(df)
        for col in salida.columns:
            if pd.api.types.is_datetime64_any_dtype(salida[col]):
                salida[col] = salida[col].dt.strftime("%Y-%m-%d")
        salida.to_csv(ruta, index=False, encoding="utf-8-sig")
        rutas.append(ruta)
    return rutas


# ----------------------------------------------------------------- Excel

def _hoja_de_datos(writer, df: pd.DataFrame, hoja: str, nombre_tabla: str, estilo="TableStyleMedium2"):
    df = limpiar(df)
    for col in COLUMNAS_BOOL:
        if col in df.columns:
            df[col] = df[col].map({True: "Sí", False: "No"})
    columnas = list(df.columns)
    df = df.rename(columns={c: ENCABEZADOS.get(c, c) for c in columnas})
    df.to_excel(writer, sheet_name=hoja, index=False)
    ws = writer.sheets[hoja]

    for i, col in enumerate(columnas, start=1):
        letra = get_column_letter(i)
        ws.column_dimensions[letra].width = ANCHOS.get(col, 14)
        if col.startswith("fecha"):
            for celda in ws[letra][1:]:
                celda.number_format = "yyyy-mm-dd"
        elif col in ("cvss_puntaje", "prioridad_puntaje", "prioridad_max"):
            for celda in ws[letra][1:]:
                celda.number_format = "0.0"
        elif col in ("epss", "epss_percentil"):
            for celda in ws[letra][1:]:
                celda.number_format = "0.00%"

    ws.freeze_panes = "B2"
    if len(df):  # una tabla de Excel necesita al menos una fila de datos
        rango = f"A1:{get_column_letter(len(columnas))}{len(df) + 1}"
        tabla = Table(displayName=nombre_tabla, ref=rango)
        tabla.tableStyleInfo = TableStyleInfo(name=estilo, showRowStripes=True)
        ws.add_table(tabla)

        for col_color, mapa in (("severidad", COLOR_SEVERIDAD), ("prioridad_nivel", COLOR_NIVEL)):
            if col_color not in columnas:
                continue
            letra = get_column_letter(columnas.index(col_color) + 1)
            zona = f"{letra}2:{letra}{len(df) + 1}"
            for valor, color in mapa.items():
                blanco = valor in ("CRÍTICA", "ALTA", "INMEDIATA", "URGENTE")
                ws.conditional_formatting.add(
                    zona,
                    CellIsRule(operator="equal", formula=[f'"{valor}"'],
                               fill=PatternFill("solid", fgColor=color),
                               font=Font(bold=True, color="FFFFFF" if blanco else "1F2937")),
                )
    return ws


def _tabla_simple(writer, df: pd.DataFrame, hoja: str, nombre_tabla: str, anchos: list[int], formatos=None):
    df.to_excel(writer, sheet_name=hoja, index=False)
    ws = writer.sheets[hoja]
    for i, ancho in enumerate(anchos, start=1):
        ws.column_dimensions[get_column_letter(i)].width = ancho
    for col, formato in (formatos or {}).items():
        letra = get_column_letter(list(df.columns).index(col) + 1)
        for celda in ws[letra][1:]:
            celda.number_format = formato
    if len(df):
        tabla = Table(displayName=nombre_tabla, ref=f"A1:{get_column_letter(len(df.columns))}{len(df) + 1}")
        tabla.tableStyleInfo = TableStyleInfo(name="TableStyleLight9", showRowStripes=True)
        ws.add_table(tabla)
    ws.freeze_panes = "A2"
    return ws


# ----------------------------------------------------------------- hoja Resumen

COLOR_FUENTE = {"NVD": "2A78D6", "CISA KEV": "EB6834", "GitHub Advisory": "1BAF7A"}
GRIS_LINEA = "E5E7EB"
ALTO_GRAFICO = 7.6      # cm (≈ 14 filas de 15 pt)
ANCHO_COMPLETO = 29.0   # cm (columnas B a L)
ANCHO_MEDIO = 14.2      # cm


def _lineas_suaves():
    return ChartLines(spPr=GraphicalProperties(ln=LineProperties(solidFill=GRIS_LINEA)))


def _etiquetas_valor() -> DataLabelList:
    """Solo el número al final de cada barra (sin nombre de serie ni de categoría)."""
    etiquetas = DataLabelList()
    etiquetas.showVal = True
    for campo in ("showSerName", "showCatName", "showLegendKey", "showPercent", "showLeaderLines"):
        setattr(etiquetas, campo, False)
    etiquetas.position = "outEnd"
    etiquetas.numFmt = "#,##0"
    return etiquetas


def _barras_horizontales(hoja, titulo: str, col_categoria: int, col_valor: int, filas: int,
                         colores: list[str] | None = None, color: str = AZUL) -> BarChart:
    """Barras horizontales limpias: categorías en orden (la mayor arriba), números al final
    de cada barra y sin eje de valores (los números ya están en las etiquetas)."""
    g = BarChart()
    g.type = "bar"
    g.title = titulo
    g.style = 10
    g.height, g.width = ALTO_GRAFICO, ANCHO_MEDIO
    g.add_data(Reference(hoja, min_col=col_valor, min_row=1, max_row=filas + 1), titles_from_data=True)
    g.set_categories(Reference(hoja, min_col=col_categoria, min_row=2, max_row=filas + 1))
    g.legend = None
    g.gapWidth = 55
    g.x_axis.scaling.orientation = "maxMin"     # el primero de la tabla arriba
    g.x_axis.delete = False
    g.x_axis.majorTickMark = "none"
    g.y_axis.delete = True                      # sin eje de números: van en las etiquetas
    g.y_axis.majorGridlines = None
    serie = g.series[0]
    serie.graphicalProperties.solidFill = color
    serie.graphicalProperties.line.noFill = True
    if colores:
        for idx, c in enumerate(colores):
            punto = DataPoint(idx=idx)
            punto.graphicalProperties.solidFill = c
            punto.graphicalProperties.line.noFill = True
            serie.dPt.append(punto)
    g.dataLabels = _etiquetas_valor()
    return g


def _hoja_resumen(wb, kpis: dict, parametros: dict, hojas: dict):
    ws = wb.create_sheet("Resumen", 0)
    ws.sheet_view.showGridLines = False
    ws.sheet_view.zoomScale = 90
    ws.page_setup.orientation = "landscape"
    ws.page_setup.fitToWidth = 1
    ws.page_setup.fitToHeight = 0
    ws.sheet_properties.pageSetUpPr.fitToPage = True
    for col, ancho in zip("ABCDEFGHIJKLM", [2, 24, 13, 2, 24, 13, 2, 24, 13, 2, 24, 13, 2]):
        ws.column_dimensions[col].width = ancho

    ws.merge_cells("B2:L2")
    ws["B2"] = "Vigía · Reporte de vulnerabilidades CVE"
    ws["B2"].font = Font(size=20, bold=True, color=AZUL)
    ws.merge_cells("B3:L3")
    ws["B3"] = (f"Periodo: {parametros['Desde']} a {parametros['Hasta']}   ·   "
                f"Fuentes: {parametros['Fuentes consultadas']}   ·   Generado: {parametros['Generado']}")
    ws["B3"].font = Font(size=10, color=GRIS)

    # --- Indicadores (2 filas de 4 tarjetas)
    tarjetas = [
        ("CVE únicas", kpis["CVE únicas"], AZUL),
        ("Críticas", kpis["Críticas"], COLOR_SEVERIDAD["CRÍTICA"]),
        ("Altas", kpis["Altas"], COLOR_SEVERIDAD["ALTA"]),
        ("CVSS promedio", kpis["CVSS promedio"] if kpis["CVSS promedio"] is not None else "—", "2E86C1"),
        ("Explotadas activamente", kpis["Explotadas activamente"], "7D3C98"),
        ("Usadas en ransomware", kpis["Usadas en ransomware"], "922B21"),
        ("Prioridad INMEDIATA", kpis.get("Prioridad inmediata", "—"), COLOR_NIVEL["INMEDIATA"]),
        ("Afectan al inventario", kpis.get("Afectan al inventario", "—"), "1B5E9C"),
    ]
    posiciones = [("B", "C"), ("E", "F"), ("H", "I"), ("K", "L")]
    for i, (titulo, valor, color) in enumerate(tarjetas):
        fila = 5 + (i // 4) * 3
        c1, c2 = posiciones[i % 4]
        ws.merge_cells(f"{c1}{fila}:{c2}{fila}")
        ws.merge_cells(f"{c1}{fila + 1}:{c2}{fila + 1}")
        ws[f"{c1}{fila}"] = titulo
        ws[f"{c1}{fila}"].font = Font(size=10, color=GRIS, bold=True)
        ws[f"{c1}{fila}"].alignment = Alignment(horizontal="left", vertical="bottom", indent=1)
        celda = ws[f"{c1}{fila + 1}"]
        celda.value = valor
        celda.font = Font(size=22, bold=True, color=color)
        celda.alignment = Alignment(horizontal="left", vertical="center", indent=1)
        celda.number_format = "0.00" if isinstance(valor, float) else "#,##0"
        ws.row_dimensions[fila + 1].height = 34
        for f in (fila, fila + 1):
            ws[f"{c1}{f}"].border = Border(left=Side(style="thick", color=color))
            for c in (c1, c2):
                ws[f"{c}{f}"].fill = PatternFill("solid", fgColor=AZUL_CLARO)

    # --- Registros por fuente (tabla pequeña, filas 12-15; los gráficos empiezan en la 18)
    ws["B12"] = "Registros por fuente"
    ws["B12"].font = Font(bold=True, color=AZUL)
    for j, (fuente, n) in enumerate(kpis["Registros por fuente"].items(), start=1):
        ws[f"B{12 + j}"] = fuente
        ws[f"C{12 + j}"] = n
        ws[f"C{12 + j}"].number_format = "#,##0"
        ws[f"C{12 + j}"].alignment = Alignment(horizontal="right")

    # --- 1) Tendencia (ancho completo)
    t = hojas["Tendencia"]
    puntos = t.max_row - 1
    if puntos >= 1 and t.max_column >= 2:
        g = LineChart()
        g.title = f"CVE publicadas por {t['A1'].value.lower()} y por fuente"
        g.style = 10
        g.height, g.width = ALTO_GRAFICO, ANCHO_COMPLETO
        g.add_data(Reference(t, min_col=2, max_col=t.max_column, min_row=1, max_row=t.max_row), titles_from_data=True)
        g.set_categories(Reference(t, min_col=1, min_row=2, max_row=t.max_row))
        for serie in g.series:
            nombre = serie.tx.strRef.f if serie.tx and serie.tx.strRef else ""
            serie.smooth = False
            serie.marker.symbol = "circle" if puntos <= 3 else "none"
            serie.graphicalProperties.line.width = 22000
        for serie, col in zip(g.series, range(2, t.max_column + 1)):
            color = COLOR_FUENTE.get(t.cell(row=1, column=col).value, GRIS)
            serie.graphicalProperties.line.solidFill = color
            if serie.marker.symbol == "circle":
                serie.marker.graphicalProperties = GraphicalProperties(solidFill=color)
                serie.marker.graphicalProperties.line.solidFill = color
        g.legend.position = "b"
        g.x_axis.delete = False
        g.y_axis.delete = False
        g.x_axis.number_format = "@"
        g.x_axis.majorTickMark = "none"
        g.x_axis.tickLblSkip = max(1, puntos // 12)
        g.x_axis.tickMarkSkip = max(1, puntos // 12)
        g.y_axis.majorGridlines = _lineas_suaves()
        g.y_axis.number_format = "#,##0"
        ws.add_chart(g, "B18")

    # --- 2) Severidad y nivel de prioridad
    sev = hojas["Por_Severidad"]
    if sev.max_row > 1:
        colores = [COLOR_SEVERIDAD.get(sev.cell(row=i, column=1).value, "999999") for i in range(2, sev.max_row + 1)]
        ws.add_chart(_barras_horizontales(sev, "CVE por severidad (CVSS)", 1, 2, sev.max_row - 1, colores), "B35")
    niv = hojas.get("Por_Prioridad")
    if niv is not None and niv.max_row > 1:
        colores = [COLOR_NIVEL.get(niv.cell(row=i, column=1).value, "999999") for i in range(2, niv.max_row + 1)]
        ws.add_chart(_barras_horizontales(niv, "CVE por nivel de prioridad", 1, 3, niv.max_row - 1, colores), "H35")

    # --- 3) Proveedores y debilidades
    prov = hojas["Top_Proveedores"]
    if prov.max_row > 1:
        ws.add_chart(_barras_horizontales(prov, "Proveedores con más CVE", 1, 2, min(prov.max_row - 1, 10)), "B52")
    cwe = hojas["Top_CWE"]
    if cwe.max_row > 1:
        ws.add_chart(_barras_horizontales(cwe, "Debilidades (CWE) más comunes", 4, 3, min(cwe.max_row - 1, 10),
                                          color="2E86C1"), "H52")
    return ws


def _cwe_con_etiqueta(top_cwe: pd.DataFrame) -> pd.DataFrame:
    """Agrega 'Etiqueta' = 'CWE-79 · Cross-site scripting (XSS)' para el gráfico."""
    df = top_cwe.copy()
    if df.empty:
        df["Etiqueta"] = pd.Series(dtype=str)
        return df
    df["Etiqueta"] = [
        f"{c} · {d}" if d else c for c, d in zip(df["CWE"], df["Debilidad"].fillna(""))
    ]
    df["Etiqueta"] = df["Etiqueta"].map(lambda t: t if len(t) <= 46 else t[:45] + "…")
    return df


def _tabla_tendencia(registros: pd.DataFrame, desde: date, hasta: date) -> pd.DataFrame:
    """Diaria para rangos cortos (≤ 92 días) y mensual para rangos largos."""
    serie = serie_temporal(registros, desde, hasta)
    columna = "Día" if serie["granularidad"] == "día" else "Mes"
    df = pd.DataFrame({columna: serie["etiquetas"], **serie["series"]})
    if columna == "Día":
        df[columna] = df[columna].str[5:]  # 2026-10-05 -> 10-05
    return df


def exportar_excel(
    ruta: Path,
    registros: pd.DataFrame,
    consolidado: pd.DataFrame,
    resumenes: dict[str, pd.DataFrame],
    kpis: dict,
    parametros: dict,
    desde: date | None = None,
    hasta: date | None = None,
) -> Path:
    ruta.parent.mkdir(parents=True, exist_ok=True)
    desde = desde or date.fromisoformat(str(parametros["Desde"]))
    hasta = hasta or date.fromisoformat(str(parametros["Hasta"]))
    with pd.ExcelWriter(ruta, engine="openpyxl") as writer:
        top = resumenes.get("prioridad")
        if top is not None:
            cols = [c for c in COLUMNAS_PRIORIDAD if c in top.columns]
            _hoja_de_datos(writer, top[cols], "Prioridad", "tblPrioridad", estilo="TableStyleMedium3")
        if resumenes.get("afectaciones") is not None:
            _hoja_de_datos(writer, resumenes["por_activo"], "Activos", "tblActivos", estilo="TableStyleMedium6")
            _hoja_de_datos(writer, resumenes["afectaciones"], "Inventario", "tblInventario", estilo="TableStyleMedium6")
        _hoja_de_datos(writer, consolidado, "Consolidado", "tblConsolidado")
        _hoja_de_datos(writer, registros, "Registros", "tblRegistros", estilo="TableStyleMedium9")
        hojas = {
            "Por_Mes": _tabla_simple(writer, resumenes["por_mes"], "Por_Mes", "tblPorMes",
                                     [10] + [16] * (len(resumenes["por_mes"].columns) - 1)),
            "Por_Severidad": _tabla_simple(writer, resumenes["por_severidad"], "Por_Severidad", "tblSeveridad",
                                           [16, 12, 12], {"Porcentaje": "0.0%"}),
            "Top_Proveedores": _tabla_simple(writer, resumenes["top_proveedores"], "Top_Proveedores",
                                             "tblProveedores", [30, 10, 10, 12]),
            "Top_CWE": _tabla_simple(writer, _cwe_con_etiqueta(resumenes["top_cwe"]), "Top_CWE", "tblCWE",
                                     [12, 44, 10, 48]),
            "Tendencia": _tabla_simple(writer, _tabla_tendencia(registros, desde, hasta), "Tendencia",
                                       "tblTendencia", [12, 14, 14, 16]),
        }
        if resumenes.get("niveles") is not None:
            hojas["Por_Prioridad"] = _tabla_simple(writer, resumenes["niveles"], "Por_Prioridad", "tblPrioridadNiveles",
                                                   [16, 26, 10])
        param = pd.DataFrame({"Parámetro": list(parametros.keys()), "Valor": [str(v) for v in parametros.values()]})
        _tabla_simple(writer, param, "Parametros", "tblParametros", [28, 100])

        wb = writer.book
        _hoja_resumen(wb, kpis, parametros, hojas)
        wb.active = 0
        wb.properties.title = "Reporte de vulnerabilidades CVE"
        wb.properties.creator = f"Vigía {__version__}"
    return ruta


def exportar(
    carpeta_salida: str | Path,
    formato: str,
    desde: date,
    hasta: date,
    registros: pd.DataFrame,
    consolidado: pd.DataFrame,
    resumenes: dict[str, pd.DataFrame],
    kpis: dict,
    parametros: dict,
) -> list[Path]:
    carpeta = Path(carpeta_salida)
    rutas: list[Path] = []
    if formato in ("excel", "ambos"):
        rutas.append(exportar_excel(carpeta / f"{_nombre_base(desde, hasta)}.xlsx",
                                    registros, consolidado, resumenes, kpis, parametros, desde, hasta))
    if formato in ("csv", "ambos"):
        tablas = {
            "consolidado": consolidado,
            **({"inventario_afectaciones": resumenes["afectaciones"]}
               if resumenes.get("afectaciones") is not None else {}),
            "registros": registros,
            "cwe_por_cve": resumenes["cwe_por_cve"],
            "por_mes": resumenes["por_mes"],
        }
        rutas.extend(exportar_csv(tablas, carpeta / "powerbi"))
    return rutas
