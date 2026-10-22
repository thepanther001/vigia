"""Enriquecimiento opcional con EPSS (FIRST.org).

EPSS = Exploit Prediction Scoring System: probabilidad (0 a 1) de que una CVE
sea explotada en los próximos 30 días. Complementa al CVSS, que mide gravedad
pero no probabilidad. API: https://www.first.org/epss/api
"""

from __future__ import annotations

from cve_explorer.cliente_http import ClienteHTTP, ErrorFuente

URL = "https://api.first.org/data/v1/epss"
LOTE = 100  # CVE por solicitud (la API acepta una lista separada por comas)


class ClienteEPSS(ClienteHTTP):
    nombre = "EPSS"

    def obtener(self, cves: list[str]) -> dict[str, tuple[float, float]]:
        """Devuelve {cve: (epss, percentil)} para las CVE que tengan puntaje."""
        cves = sorted({c for c in cves if c and c.startswith("CVE-")})
        resultado: dict[str, tuple[float, float]] = {}
        for i in range(0, len(cves), LOTE):
            lote = cves[i : i + LOTE]
            try:
                datos = self._get(URL, params={"cve": ",".join(lote), "limit": LOTE}, intentos=3).json()
            except (ErrorFuente, ValueError) as error:
                self.log(f"   ! EPSS: se omitió un lote ({error})")
                continue
            for fila in datos.get("data", []):
                resultado[fila["cve"]] = (float(fila["epss"]), float(fila["percentile"]))
            hechos = min(i + LOTE, len(cves))
            if hechos % 1000 == 0 or hechos == len(cves):
                self.log(f"   EPSS: {hechos}/{len(cves)}")
            self._esperar(0.2)
        return resultado
