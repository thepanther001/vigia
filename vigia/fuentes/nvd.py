"""Fuente: NVD — National Vulnerability Database (NIST), API CVE 2.0.

Documentación: https://nvd.nist.gov/developers/vulnerabilities
Reglas importantes de la API:
  * El rango de fechas por consulta no puede pasar de 120 días -> se divide en tramos.
  * Máximo 2000 resultados por página -> se pagina con startIndex.
  * Sin llave: ~5 solicitudes cada 30 s (pausa de 6 s). Con llave: ~50 cada 30 s.
"""

from __future__ import annotations

from datetime import date
from typing import Optional
from urllib.parse import urlencode

from vigia.cliente_http import ErrorFuente
from vigia.fechas import dividir_rango
from vigia.fuentes.base import FuenteBase
from vigia.modelo import (
    FUENTE_NVD,
    Registro,
    fecha_iso,
    nombre_proveedor,
    normalizar_severidad,
    unicos,
)

URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
MAX_DIAS = 120
POR_PAGINA = 2000

# Orden de preferencia de las métricas CVSS (la más moderna primero).
METRICAS = [
    ("cvssMetricV40", "4.0"),
    ("cvssMetricV31", "3.1"),
    ("cvssMetricV30", "3.0"),
    ("cvssMetricV2", "2.0"),
]


def _elegir_metrica(lista: list) -> dict:
    """Prefiere la calificación 'Primary' (la de NIST) sobre la 'Secondary' (la del fabricante)."""
    for m in lista:
        if m.get("type") == "Primary":
            return m
    return lista[0]


def extraer_cvss(metricas: dict) -> tuple[Optional[float], Optional[str], Optional[str], Optional[str]]:
    """Devuelve (puntaje, versión, vector, severidad) de la mejor métrica disponible."""
    for clave, version in METRICAS:
        lista = metricas.get(clave) or []
        if not lista:
            continue
        m = _elegir_metrica(lista)
        datos = m.get("cvssData", {})
        # En CVSS v2 la severidad está fuera de cvssData; en v3/v4 está adentro.
        severidad = datos.get("baseSeverity") or m.get("baseSeverity")
        return datos.get("baseScore"), datos.get("version", version), datos.get("vectorString"), severidad
    return None, None, None, None


def extraer_cpe(configuraciones: list) -> tuple[Optional[str], Optional[str]]:
    """Saca proveedor y productos de los CPE: 'cpe:2.3:a:apache:log4j:2.14:*...'."""
    proveedores, productos = [], []
    for conf in configuraciones or []:
        for nodo in conf.get("nodes", []):
            for match in nodo.get("cpeMatch", []):
                partes = match.get("criteria", "").split(":")
                if len(partes) > 4:
                    proveedores.append(partes[3])
                    productos.append(partes[4].replace("_", " "))
    proveedores = unicos(proveedores)
    productos = [p for p in unicos(productos) if p not in ("*", "-")]
    proveedor = nombre_proveedor(proveedores[0]) if proveedores else None
    producto = ", ".join(productos[:3]) if productos else None
    return proveedor, producto


def extraer_descripcion(descripciones: list, idioma: str = "es") -> Optional[str]:
    """Usa la descripción en el idioma pedido; si no existe, la de inglés."""
    por_idioma = {d.get("lang"): d.get("value") for d in descripciones or []}
    return por_idioma.get(idioma) or por_idioma.get("en") or next(iter(por_idioma.values()), None)


def parsear_cve(cve: dict, idioma: str = "es") -> Registro:
    """Convierte un objeto 'cve' de la API NVD 2.0 al Registro común."""
    puntaje, version, vector, severidad = extraer_cvss(cve.get("metrics", {}))
    proveedor, producto = extraer_cpe(cve.get("configurations", []))
    cwes = unicos(
        d.get("value")
        for w in cve.get("weaknesses", [])
        for d in w.get("description", [])
        if str(d.get("value", "")).startswith("CWE-")
    )
    cve_id = cve.get("id")
    return Registro(
        fuente=FUENTE_NVD,
        cve_id=cve_id,
        id_fuente=cve_id,
        titulo=cve.get("cisaVulnerabilityName"),
        descripcion=extraer_descripcion(cve.get("descriptions", []), idioma),
        fecha_publicacion=fecha_iso(cve.get("published")),
        fecha_actualizacion=fecha_iso(cve.get("lastModified")),
        severidad=normalizar_severidad(severidad, puntaje),
        cvss_puntaje=puntaje,
        cvss_version=version,
        cvss_vector=vector,
        cwe="; ".join(cwes) or None,
        proveedor=proveedor,
        producto=producto,
        # La NVD marca con cisaExploitAdd las CVE que también están en el catálogo KEV.
        explotada_activamente=True if cve.get("cisaExploitAdd") else None,
        estado=cve.get("vulnStatus"),
        url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
    )


class FuenteNVD(FuenteBase):
    clave = "nvd"
    nombre = FUENTE_NVD
    descripcion = "National Vulnerability Database (NIST) — catálogo oficial de CVE con CVSS, CWE y CPE"
    sitio = "https://nvd.nist.gov"

    def __init__(self, api_key: Optional[str] = None, idioma: str = "es", **kwargs):
        super().__init__(**kwargs)
        self.api_key = api_key
        self.idioma = idioma
        # Pausa entre solicitudes para no pasar el límite de la NVD.
        self.pausa = 0.7 if api_key else 6.5

    def _es_limite_de_tasa(self, resp) -> bool:
        # La NVD responde 403 (no solo 429) cuando se excede el límite.
        return resp.status_code in (403, 429)

    def buscar_por_ids(self, cve_ids: list[str], maximo: Optional[int] = None) -> list[Registro]:
        """Consulta CVE puntuales (parámetro cveId). Se usa para completar el CVSS
        de las CVE de CISA KEV, que suelen ser antiguas y no caen en el rango de fechas."""
        if maximo is None:
            maximo = 300 if self.api_key else 40
        ids = list(dict.fromkeys(c for c in cve_ids if c and c.startswith("CVE-")))
        if len(ids) > maximo:
            self._avisar(
                f"NVD: solo se completaron {maximo} de {len(ids)} CVE de KEV sin CVSS "
                "(con NVD_API_KEY el límite sube a 300)."
            )
            ids = ids[:maximo]
        headers = {"apiKey": self.api_key} if self.api_key else None
        registros: list[Registro] = []
        for n, cve_id in enumerate(ids, start=1):
            try:
                datos = self._get(URL, params={"cveId": cve_id}, headers=headers, intentos=3).json()
            except ErrorFuente as error:
                if error.codigo is None:  # sin conexión: no tiene sentido seguir intentando
                    self._avisar(f"NVD no responde; no se pudo completar el CVSS de KEV ({error}).")
                    break
                self.log(f"   ! NVD {cve_id}: {error}")  # una CVE que falla no detiene el resto
                continue
            for item in datos.get("vulnerabilities", []):
                registros.append(parsear_cve(item.get("cve", {}), self.idioma))
            if n % 10 == 0 or n == len(ids):
                self.log(f"   NVD (completando KEV): {n}/{len(ids)}")
            if n < len(ids):
                self._esperar(self.pausa)
        return registros

    def consultar(self, desde: date, hasta: date) -> list[Registro]:
        headers = {"apiKey": self.api_key} if self.api_key else None
        if not self.api_key:
            self.log("   (sin NVD_API_KEY: irá lento, ~6 s por página. Ver README para pedir una gratis)")

        tramos = list(dividir_rango(desde, hasta, MAX_DIAS))
        registros: list[Registro] = []

        for n, (ini, fin) in enumerate(tramos, start=1):
            inicio = 0
            while True:
                params = {
                    "pubStartDate": f"{ini.isoformat()}T00:00:00.000",
                    "pubEndDate": f"{fin.isoformat()}T23:59:59.999",
                    "resultsPerPage": POR_PAGINA,
                    "startIndex": inicio,
                }
                # noRejected es un parámetro sin valor: excluye CVE rechazadas.
                url = f"{URL}?{urlencode(params)}&noRejected"
                datos = self._get(url, headers=headers).json()

                total = datos.get("totalResults", 0)
                vulnerabilidades = datos.get("vulnerabilities", [])
                for item in vulnerabilidades:
                    registros.append(parsear_cve(item.get("cve", {}), self.idioma))
                    if self._alcanzo_limite(len(registros)):
                        self.log(f"   NVD: límite de {self.limite} registros alcanzado")
                        return registros

                inicio += len(vulnerabilidades)
                self.log(f"   NVD tramo {n}/{len(tramos)} ({ini} → {fin}): {inicio}/{total}")

                if not vulnerabilidades or inicio >= total:
                    break
                self._esperar(self.pausa)

            if n < len(tramos):
                self._esperar(self.pausa)

        return registros
