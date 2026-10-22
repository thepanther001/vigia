"""Registro de las bases de datos disponibles.

Para agregar una fuente nueva: crear su módulo heredando de FuenteBase
y añadirla al diccionario FUENTES.
"""

from cve_explorer.fuentes.base import FuenteBase
from cve_explorer.fuentes.cisa_kev import FuenteCISAKEV
from cve_explorer.fuentes.github_advisory import FuenteGitHub
from cve_explorer.fuentes.nvd import FuenteNVD

FUENTES: dict[str, type[FuenteBase]] = {
    FuenteNVD.clave: FuenteNVD,
    FuenteCISAKEV.clave: FuenteCISAKEV,
    FuenteGitHub.clave: FuenteGitHub,
}

__all__ = ["FUENTES", "FuenteBase", "FuenteNVD", "FuenteCISAKEV", "FuenteGitHub"]
