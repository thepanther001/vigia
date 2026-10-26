"""Fuente: GitHub Advisory Database (avisos revisados por GitHub).

Documentación: https://docs.github.com/en/rest/security-advisories/global-advisories
Fuerte en vulnerabilidades de librerías de código abierto (npm, pip, Maven, NuGet...).
  * Sin token: 60 solicitudes por hora. Con token: 5000 por hora.
  * En GitHub Codespaces la variable GITHUB_TOKEN ya existe, así que se usa sola.
  * Paginación por cursor usando el encabezado 'Link' (rel="next").
"""

from __future__ import annotations

import time
from datetime import date
from typing import Optional

from vigia.fuentes.base import FuenteBase
from vigia.cliente_http import ErrorFuente
from vigia.modelo import (
    FUENTE_GHSA,
    Registro,
    fecha_iso,
    normalizar_severidad,
    unicos,
    version_de_vector,
)

URL = "https://api.github.com/advisories"
POR_PAGINA = 100
MAX_ESPERA_LIMITE = 90  # segundos; si hay que esperar más, se entrega lo que haya


class LimiteGitHubAgotado(ErrorFuente):
    """Se acabó la cuota por hora de la API de GitHub."""


def extraer_cvss_ghsa(adv: dict) -> tuple[Optional[float], Optional[str], Optional[str]]:
    """GitHub puede traer CVSS v4 y v3; se prefiere v4. Puntaje 0 = sin dato."""
    severidades = adv.get("cvss_severities") or {}
    for clave, version in (("cvss_v4", "4.0"), ("cvss_v3", "3.1")):
        datos = severidades.get(clave) or {}
        if datos.get("score"):
            vector = datos.get("vector_string")
            return float(datos["score"]), version_de_vector(vector, version), vector
    antiguo = adv.get("cvss") or {}  # campo viejo, todavía presente
    if antiguo.get("score"):
        vector = antiguo.get("vector_string")
        return float(antiguo["score"]), version_de_vector(vector, "3.1"), vector
    return None, None, None


def parsear_advisory(adv: dict, incluir_sin_cve: bool = False) -> Optional[Registro]:
    cve_id = adv.get("cve_id")
    if not cve_id and not incluir_sin_cve:
        return None

    puntaje, version, vector = extraer_cvss_ghsa(adv)
    paquetes = [v.get("package") or {} for v in adv.get("vulnerabilities") or []]
    ecosistemas = unicos(p.get("ecosystem") for p in paquetes)
    nombres = unicos(p.get("name") for p in paquetes)
    cwes = unicos(c.get("cwe_id") for c in adv.get("cwes") or [])

    return Registro(
        fuente=FUENTE_GHSA,
        cve_id=cve_id or adv.get("ghsa_id"),
        id_fuente=adv.get("ghsa_id"),
        titulo=adv.get("summary"),
        descripcion=adv.get("description"),
        fecha_publicacion=fecha_iso(adv.get("published_at")),
        fecha_actualizacion=fecha_iso(adv.get("updated_at")),
        severidad=normalizar_severidad(adv.get("severity"), puntaje),
        cvss_puntaje=puntaje,
        cvss_version=version,
        cvss_vector=vector,
        cwe="; ".join(cwes) or None,
        producto=", ".join(nombres[:3]) or None,
        ecosistema=", ".join(ecosistemas) or None,
        estado="Retirado" if adv.get("withdrawn_at") else "Revisado",
        url=adv.get("html_url"),
    )


class FuenteGitHub(FuenteBase):
    clave = "ghsa"
    nombre = FUENTE_GHSA
    descripcion = "GitHub Advisory Database — vulnerabilidades en librerías y paquetes de código abierto"
    sitio = "https://github.com/advisories"

    def __init__(self, token: Optional[str] = None, incluir_sin_cve: bool = False, **kwargs):
        super().__init__(**kwargs)
        self.token = token
        self.incluir_sin_cve = incluir_sin_cve
        self.pausa = 0.3 if token else 1.0

    def _encabezados(self) -> dict:
        h = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
        if self.token:
            h["Authorization"] = f"Bearer {self.token}"
        return h

    def _es_limite_de_tasa(self, resp) -> bool:
        if resp.status_code == 429:
            return True
        h = resp.headers or {}
        return resp.status_code == 403 and (h.get("X-RateLimit-Remaining") == "0" or "Retry-After" in h)

    def _segundos_de_espera(self, resp, por_defecto: float) -> float:
        h = resp.headers or {}
        if h.get("X-RateLimit-Remaining") == "0" and h.get("X-RateLimit-Reset"):
            segundos = int(h["X-RateLimit-Reset"]) - time.time() + 1
            if segundos > MAX_ESPERA_LIMITE:
                minutos = max(1, round(segundos / 60))
                raise LimiteGitHubAgotado(
                    f"GitHub: se agotó la cuota por hora (se libera en ~{minutos} min). "
                    "Configura GITHUB_TOKEN para tener 5000 solicitudes/hora."
                )
            return max(segundos, 1)
        return super()._segundos_de_espera(resp, por_defecto)

    def consultar(self, desde: date, hasta: date) -> list[Registro]:
        if not self.token:
            self.log("   (sin GITHUB_TOKEN: máximo 60 solicitudes/hora ≈ 6000 avisos)")
        params = {
            "type": "reviewed",
            "published": f"{desde.isoformat()}..{hasta.isoformat()}",
            "per_page": POR_PAGINA,
            "sort": "published",
            "direction": "asc",
        }
        url: Optional[str] = URL
        registros: list[Registro] = []
        pagina = 0

        while url:
            try:
                resp = self._get(url, params=params, headers=self._encabezados())
            except LimiteGitHubAgotado as error:
                self._avisar(f"{error} Se exportan los {len(registros)} registros obtenidos hasta ahora.")
                break
            except ErrorFuente as error:
                if error.codigo == 401 and self.token:
                    self._avisar("GitHub rechazó el token (401); se continúa sin token.")
                    self.token = None
                    continue
                raise

            pagina += 1
            for adv in resp.json():
                registro = parsear_advisory(adv, self.incluir_sin_cve)
                if registro:
                    registros.append(registro)
                    if self._alcanzo_limite(len(registros)):
                        self.log(f"   GitHub: límite de {self.limite} registros alcanzado")
                        return registros

            self.log(f"   GitHub página {pagina}: {len(registros)} avisos con CVE acumulados")
            url = (resp.links or {}).get("next", {}).get("url")
            params = None  # la URL 'next' ya trae todos los parámetros
            if url:
                self._esperar(self.pausa)

        return registros
