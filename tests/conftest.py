"""Utilidades compartidas: sesión HTTP falsa para probar sin internet."""

import json
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


def cargar(nombre):
    return json.loads((FIXTURES / nombre).read_text(encoding="utf-8"))


class RespuestaFalsa:
    def __init__(self, datos=None, status_code=200, headers=None, links=None, text=""):
        self._datos = datos
        self.status_code = status_code
        self.headers = headers or {}
        self.links = links or {}
        self.text = text or json.dumps(datos)[:200]

    def json(self):
        return self._datos


class SesionFalsa:
    """Devuelve las respuestas en orden y guarda las solicitudes hechas."""

    def __init__(self, respuestas):
        self.respuestas = list(respuestas)
        self.solicitudes = []

    def get(self, url, params=None, headers=None, timeout=None):
        self.solicitudes.append({"url": url, "params": params, "headers": headers})
        return self.respuestas.pop(0)


@pytest.fixture
def silencio():
    return lambda mensaje: None


def sin_esperas(fuente):
    fuente._esperar = lambda segundos: None
    return fuente
