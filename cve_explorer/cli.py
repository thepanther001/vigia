"""Interfaz de línea de comandos (modo con argumentos y modo interactivo)."""

from __future__ import annotations

import argparse
import sys
import time
from datetime import date, datetime
from typing import Callable

from cve_explorer import __version__, config
from cve_explorer.cliente_http import ErrorFuente
from cve_explorer.epss import ClienteEPSS
from cve_explorer.exportar import exportar
from cve_explorer.fechas import (
    RangoFechasError,
    fecha_minima_permitida,
    parsear_fecha,
    rango_ultimos_dias,
    validar_rango,
)
from cve_explorer.fuentes import FUENTES, FuenteBase
from cve_explorer import procesamiento as proc

EJEMPLOS = """
ejemplos:
  python main.py                                         (menú interactivo)
  python main.py --ultimos-dias 30 --fuentes todas
  python main.py --desde 2025-01-01 --hasta 2025-06-30 --fuentes nvd,kev
  python main.py --desde 2024-01-01 --hasta 2024-12-31 --fuentes kev --formato excel
  python main.py --ultimos-dias 7 --fuentes nvd,ghsa --epss --limite 500
"""


def construir_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="cve-explorer",
        description="Consulta vulnerabilidades CVE en varias bases de datos y las exporta a Excel/CSV.",
        epilog=EJEMPLOS,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    fechas = p.add_argument_group("rango de fechas (máximo últimos 5 años)")
    fechas.add_argument("--desde", metavar="AAAA-MM-DD", help="fecha inicial")
    fechas.add_argument("--hasta", metavar="AAAA-MM-DD", help="fecha final (por defecto: hoy)")
    fechas.add_argument("--ultimos-dias", type=int, metavar="N", help="atajo: los últimos N días")

    p.add_argument("--fuentes", metavar="LISTA",
                   help=f"bases a consultar separadas por coma: {','.join(FUENTES)} o 'todas'")
    p.add_argument("--formato", choices=["excel", "csv", "ambos"], default="ambos",
                   help="tipo de exportación (por defecto: ambos)")
    p.add_argument("--salida", default=config.CARPETA_SALIDA, help="carpeta de salida (por defecto: output)")
    p.add_argument("--limite", type=int, metavar="N", help="máximo de registros por fuente (pruebas rápidas)")
    p.add_argument("--epss", action="store_true", help="agregar probabilidad de explotación EPSS (FIRST.org)")
    p.add_argument("--idioma", choices=["es", "en"], default="es",
                   help="idioma preferido de las descripciones de la NVD (por defecto: es)")
    p.add_argument("--incluir-sin-cve", action="store_true",
                   help="incluir avisos de GitHub que no tienen CVE asignado")
    p.add_argument("--listar-fuentes", action="store_true", help="mostrar las bases disponibles y salir")
    p.add_argument("-i", "--interactivo", action="store_true", help="forzar el menú interactivo")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


# ----------------------------------------------------------------- utilidades

def parsear_fuentes(texto: str | None) -> list[str]:
    if not texto or texto.strip().lower() in ("todas", "all", "*"):
        return list(FUENTES)
    claves = [c.strip().lower() for c in texto.split(",") if c.strip()]
    invalidas = [c for c in claves if c not in FUENTES]
    if invalidas:
        raise ValueError(f"Fuente(s) desconocida(s): {', '.join(invalidas)}. Opciones: {', '.join(FUENTES)}")
    return list(dict.fromkeys(claves))  # sin repetidos, en el orden escrito


def resolver_rango(args, hoy: date | None = None) -> tuple[date, date]:
    hoy = hoy or date.today()
    if args.ultimos_dias:
        return rango_ultimos_dias(args.ultimos_dias, hoy)
    if not args.desde:
        raise RangoFechasError("Indica --desde AAAA-MM-DD o --ultimos-dias N.")
    desde = parsear_fecha(args.desde)
    hasta = parsear_fecha(args.hasta) if args.hasta else hoy
    return validar_rango(desde, hasta, hoy)


def crear_fuente(clave: str, args) -> FuenteBase:
    comunes = {"limite": args.limite}
    if clave == "nvd":
        return FUENTES[clave](api_key=config.NVD_API_KEY, idioma=args.idioma, **comunes)
    if clave == "ghsa":
        return FUENTES[clave](token=config.GITHUB_TOKEN, incluir_sin_cve=args.incluir_sin_cve, **comunes)
    return FUENTES[clave](**comunes)


def listar_fuentes() -> None:
    print("\nBases de datos disponibles:\n")
    for clave, clase in FUENTES.items():
        print(f"  {clave:<6} {clase.nombre:<17} {clase.descripcion}")
        print(f"  {'':<6} {'':<17} {clase.sitio}\n")


# ----------------------------------------------------------------- modo interactivo

def _preguntar(texto: str, entrada: Callable[[str], str]) -> str:
    try:
        return entrada(texto).strip()
    except EOFError:
        return ""


def modo_interactivo(args, entrada: Callable[[str], str] = input, hoy: date | None = None):
    """Llena 'args' preguntando al usuario. Devuelve los mismos args ya completos."""
    hoy = hoy or date.today()
    minima = fecha_minima_permitida(hoy)
    print("\n" + "=" * 62)
    print(f"  CVE Explorer {__version__} — consulta de vulnerabilidades")
    print("=" * 62)

    # 1) Rango de fechas
    print(f"\n[1] Rango de fechas (permitido: {minima} a {hoy})")
    opciones = {"1": 7, "2": 30, "3": 90, "4": 365}
    print("    1) Últimos 7 días\n    2) Últimos 30 días\n    3) Últimos 90 días"
          "\n    4) Último año\n    5) Últimos 5 años\n    6) Personalizado")
    while True:
        op = _preguntar("    Opción [2]: ", entrada) or "2"
        try:
            if op in opciones:
                args.ultimos_dias, args.desde, args.hasta = opciones[op], None, None
            elif op == "5":
                args.ultimos_dias, args.desde, args.hasta = None, minima.isoformat(), hoy.isoformat()
            elif op == "6":
                args.ultimos_dias = None
                args.desde = _preguntar("    Desde (AAAA-MM-DD): ", entrada)
                args.hasta = _preguntar(f"    Hasta (AAAA-MM-DD) [{hoy}]: ", entrada) or hoy.isoformat()
            else:
                print("    ! Opción no válida")
                continue
            desde, hasta = resolver_rango(args, hoy)
            print(f"    → {desde} a {hasta}")
            break
        except RangoFechasError as error:
            print(f"    ! {error}")

    # 2) Fuentes
    print("\n[2] Bases de datos a consultar")
    claves = list(FUENTES)
    for i, clave in enumerate(claves, start=1):
        print(f"    {i}) {FUENTES[clave].nombre:<16} {FUENTES[clave].descripcion}")
    while True:
        texto = _preguntar("    Elige números separados por coma (ej. 1,2) o Enter para todas: ", entrada)
        if not texto:
            args.fuentes = "todas"
            break
        try:
            numeros = [int(n) for n in texto.replace(" ", "").split(",") if n]
            if not numeros or any(n < 1 or n > len(claves) for n in numeros):
                raise ValueError
            args.fuentes = ",".join(claves[n - 1] for n in numeros)
            break
        except ValueError:
            print("    ! Escribe números de la lista, por ejemplo: 1,3")
    print(f"    → {', '.join(FUENTES[c].nombre for c in parsear_fuentes(args.fuentes))}")

    # 3) Formato
    print("\n[3] Exportar como\n    1) Excel + CSV (Power BI)\n    2) Solo Excel\n    3) Solo CSV (Power BI)")
    args.formato = {"1": "ambos", "2": "excel", "3": "csv"}.get(_preguntar("    Opción [1]: ", entrada), "ambos")

    # 4) Extras
    args.epss = _preguntar("\n[4] ¿Agregar probabilidad de explotación EPSS? (s/N): ", entrada).lower() in ("s", "si", "sí", "y")
    limite = _preguntar("[5] Máximo de registros por fuente (Enter = sin límite): ", entrada)
    args.limite = int(limite) if limite.isdigit() and int(limite) > 0 else None
    return args


# ----------------------------------------------------------------- ejecución

def ejecutar(args) -> int:
    try:
        desde, hasta = resolver_rango(args)
        claves = parsear_fuentes(args.fuentes)
    except (RangoFechasError, ValueError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 2

    inicio = time.time()
    print(f"\nConsultando del {desde} al {hasta} en: {', '.join(FUENTES[c].nombre for c in claves)}\n")

    registros, estado_fuentes, advertencias = [], {}, []
    for clave in claves:
        fuente = crear_fuente(clave, args)
        print(f"▶ {fuente.nombre}")
        try:
            datos = fuente.consultar(desde, hasta)
            registros.extend(datos)
            estado_fuentes[fuente.nombre] = f"OK — {len(datos)} registros"
            print(f"  ✔ {len(datos)} registros\n")
        except ErrorFuente as error:
            estado_fuentes[fuente.nombre] = f"ERROR — {error}"
            advertencias.append(str(error))
            print(f"  ✘ {error}\n")
        advertencias.extend(fuente.advertencias)

    if not registros:
        print("No se obtuvo ningún registro. Revisa la conexión o amplía el rango de fechas.")
        return 1

    print("Procesando datos...")
    df_registros = proc.registros_a_df(registros)
    df_consolidado = proc.consolidar(df_registros)

    if args.epss:
        print("▶ EPSS (FIRST.org)")
        puntajes = ClienteEPSS().obtener(df_consolidado["cve_id"].tolist())
        df_consolidado = proc.agregar_epss(df_consolidado, puntajes)
        print(f"  ✔ {len(puntajes)} CVE con puntaje EPSS\n")

    nombres = [FUENTES[c].nombre for c in claves]
    resumenes = {
        "por_mes": proc.tabla_por_mes(df_registros, df_consolidado, desde, hasta, nombres),
        "por_severidad": proc.tabla_por_severidad(df_consolidado),
        "top_proveedores": proc.tabla_top_proveedores(df_consolidado),
        "top_cwe": proc.tabla_top_cwe(df_consolidado),
        "cwe_por_cve": proc.tabla_cwe_por_cve(df_consolidado),
    }
    kpis = proc.indicadores(df_consolidado, df_registros)
    parametros = {
        "Generado": datetime.now().strftime("%Y-%m-%d %H:%M"),
        "Desde": desde.isoformat(),
        "Hasta": hasta.isoformat(),
        "Fuentes consultadas": ", ".join(nombres),
        **{f"Resultado {k}": v for k, v in estado_fuentes.items()},
        "Criterio de fecha": "NVD/GitHub: fecha de publicación · CISA KEV: fecha en que se agregó al catálogo",
        "Límite por fuente": args.limite or "Sin límite",
        "EPSS": "Sí" if args.epss else "No",
        "Advertencias": " | ".join(advertencias) or "Ninguna",
        "Versión del programa": __version__,
    }

    rutas = exportar(args.salida, args.formato, desde, hasta, df_registros, df_consolidado,
                     resumenes, kpis, parametros)

    print("\n" + "─" * 50)
    print(f"  CVE únicas:              {kpis['CVE únicas']:>8,}")
    print(f"  Críticas:                {kpis['Críticas']:>8,}")
    print(f"  Altas:                   {kpis['Altas']:>8,}")
    print(f"  Explotadas activamente:  {kpis['Explotadas activamente']:>8,}")
    print(f"  Usadas en ransomware:    {kpis['Usadas en ransomware']:>8,}")
    print("─" * 50)
    print("Archivos generados:")
    for ruta in rutas:
        print(f"  • {ruta}")
    if advertencias:
        print("\nAdvertencias:")
        for a in advertencias:
            print(f"  ! {a}")
    print(f"\nListo en {time.time() - inicio:.1f} s")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = construir_parser()
    args = parser.parse_args(argv)

    if args.listar_fuentes:
        listar_fuentes()
        return 0

    sin_parametros = not (args.desde or args.ultimos_dias or args.fuentes)
    if args.interactivo or sin_parametros:
        try:
            args = modo_interactivo(args)
        except KeyboardInterrupt:
            print("\nCancelado.")
            return 130

    try:
        return ejecutar(args)
    except KeyboardInterrupt:
        print("\nCancelado por el usuario.")
        return 130
