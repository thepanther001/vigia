"""Registro de las bases de datos disponibles.

Para agregar una fuente nueva: crear su módulo heredando de FuenteBase
y añadirla al diccionario FUENTES.
"""

from vigia.fuentes.base import FuenteBase
from vigia.fuentes.cisa_kev import FuenteCISAKEV
from vigia.fuentes.github_advisory import FuenteGitHub
from vigia.fuentes.nvd import FuenteNVD

FUENTES: dict[str, type[FuenteBase]] = {
    FuenteNVD.clave: FuenteNVD,
    FuenteCISAKEV.clave: FuenteCISAKEV,
    FuenteGitHub.clave: FuenteGitHub,
}

__all__ = ["FUENTES", "FuenteBase", "FuenteNVD", "FuenteCISAKEV", "FuenteGitHub"]
