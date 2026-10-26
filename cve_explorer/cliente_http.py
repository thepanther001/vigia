"""Cliente HTTP con reintentos y respeto de los límites de velocidad de cada API."""

from __future__ import annotations

import time
from typing import Callable, Optional

import requests

from cve_explorer.config import TIMEOUT, USER_AGENT


class ErrorFuente(Exception):
    """Error al consultar una fuente (red caída, HTTP 4xx/5xx, límite agotado...)."""

    def __init__(self, mensaje: str, codigo: Optional[int] = None):
        super().__init__(mensaje)
        self.codigo = codigo


def crear_sesion() -> requests.Session:
    sesion = requests.Session()
    sesion.headers.update({"User-Agent": USER_AGENT})
    return sesion


class ClienteHTTP:
    """Base reutilizable: GET con reintentos y espera exponencial (backoff)."""

    nombre = "HTTP"
    CODIGOS_REINTENTABLES = (500, 502, 503, 504)

    def __init__(self, sesion=None, log: Optional[Callable[[str], None]] = None):
        self.sesion = sesion or crear_sesion()
        self.log = log or (lambda mensaje: print(mensaje, flush=True))

    # Se separa en un método para poder "saltar" las esperas en las pruebas.
    def _esperar(self, segundos: float) -> None:
        if segundos > 0:
            time.sleep(segundos)

    def _es_limite_de_tasa(self, resp) -> bool:
        """¿La API respondió que vamos demasiado rápido?"""
        return resp.status_code == 429

    def _segundos_de_espera(self, resp, por_defecto: float) -> float:
        valor = (resp.headers or {}).get("Retry-After")
        if valor and str(valor).isdigit():
            return float(valor)
        return por_defecto

    def _get(self, url: str, params=None, headers=None, intentos: int = 5):
        espera = 5.0
        for intento in range(1, intentos + 1):
            try:
                resp = self.sesion.get(url, params=params, headers=headers, timeout=TIMEOUT)
            except requests.RequestException as error:
                if intento == intentos:
                    raise ErrorFuente(f"{self.nombre}: sin conexión ({type(error).__name__})") from error
                self.log(f"   ! {self.nombre}: error de red, reintento {intento}/{intentos - 1} en {espera:.0f}s")
                self._esperar(espera)
                espera = min(espera * 2, 120)
                continue

            if resp.status_code == 200:
                return resp

            reintentable = resp.status_code in self.CODIGOS_REINTENTABLES or self._es_limite_de_tasa(resp)
            if reintentable and intento < intentos:
                segundos = self._segundos_de_espera(resp, espera)
                self.log(
                    f"   ! {self.nombre}: HTTP {resp.status_code}, reintento {intento}/{intentos - 1} "
                    f"en {segundos:.0f}s"
                )
                self._esperar(segundos)
                espera = min(espera * 2, 120)
                continue

            detalle = (resp.text or "")[:200].replace("\n", " ")
            raise ErrorFuente(f"{self.nombre}: HTTP {resp.status_code} — {detalle}", resp.status_code)

        raise ErrorFuente(f"{self.nombre}: sin respuesta después de {intentos} intentos")
