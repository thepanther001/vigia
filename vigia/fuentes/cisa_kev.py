"""Fuente: CISA KEV — Known Exploited Vulnerabilities Catalog.

Lista oficial del gobierno de EE.UU. con las CVE que se están explotando
activamente en ataques reales. Se descarga completo (es un JSON de ~1 MB)
y se filtra por la fecha en que CISA agregó cada vulnerabilidad (dateAdded).
"""

from __future__ import annotations

from datetime import date

from vigia.fuentes.base import FuenteBase
from vigia.cliente_http import ErrorFuente
from vigia.modelo import FUENTE_KEV, Registro, fecha_iso, unicos

URLS = [
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    # Espejo oficial de CISA en GitHub, por si el sitio principal falla.
    "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json",
]


def _ransomware(valor) -> str:
    return "Sí" if str(valor).strip().lower() == "known" else "Desconocido"


def parsear_kev(v: dict) -> Registro:
    cve_id = v.get("cveID")
    cwes = unicos(c for c in v.get("cwes", []) if str(c).startswith("CWE-"))
    return Registro(
        fuente=FUENTE_KEV,
        cve_id=cve_id,
        id_fuente=cve_id,
        titulo=v.get("vulnerabilityName"),
        descripcion=v.get("shortDescription"),
        fecha_publicacion=fecha_iso(v.get("dateAdded")),
        cwe="; ".join(cwes) or None,
        proveedor=v.get("vendorProject"),
        producto=v.get("product"),
        explotada_activamente=True,
        ransomware=_ransomware(v.get("knownRansomwareCampaignUse")),
        fecha_limite_cisa=fecha_iso(v.get("dueDate")),
        estado=v.get("requiredAction"),
        url=f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext={cve_id}",
    )


class FuenteCISAKEV(FuenteBase):
    clave = "kev"
    nombre = FUENTE_KEV
    descripcion = "CISA Known Exploited Vulnerabilities — CVE explotadas activamente en ataques reales"
    sitio = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"

    def _descargar(self) -> dict:
        ultimo_error = None
        for url in URLS:
            try:
                return self._get(url, intentos=2).json()
            except (ErrorFuente, ValueError) as error:
                ultimo_error = error
                self.log(f"   ! KEV: no se pudo usar {url.split('/')[2]}, probando la siguiente dirección...")
        raise ErrorFuente(f"CISA KEV: no se pudo descargar el catálogo ({ultimo_error})")

    def consultar(self, desde: date, hasta: date) -> list[Registro]:
        catalogo = self._descargar()
        self.log(
            f"   KEV versión {catalogo.get('catalogVersion')} — "
            f"{catalogo.get('count', len(catalogo.get('vulnerabilities', [])))} entradas en el catálogo"
        )
        registros = []
        for v in catalogo.get("vulnerabilities", []):
            agregada = fecha_iso(v.get("dateAdded"))
            if agregada and desde <= agregada <= hasta:
                registros.append(parsear_kev(v))
                if self._alcanzo_limite(len(registros)):
                    break
        self.log(f"   KEV: {len(registros)} agregadas entre {desde} y {hasta}")
        return registros
