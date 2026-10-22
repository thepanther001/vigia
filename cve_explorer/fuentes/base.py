"""Clase base que toda fuente de vulnerabilidades debe implementar."""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import date
from typing import Optional

from cve_explorer.cliente_http import ClienteHTTP
from cve_explorer.modelo import Registro


class FuenteBase(ClienteHTTP, ABC):
    """Para agregar una base de datos nueva: heredar de aquí e implementar consultar()."""

    clave = ""        # identificador corto para la línea de comandos (ej. "nvd")
    nombre = ""       # nombre que sale en los reportes
    descripcion = ""  # explicación corta para el menú
    sitio = ""        # página oficial

    def __init__(self, sesion=None, limite: Optional[int] = None, log=None):
        super().__init__(sesion=sesion, log=log)
        self.limite = limite          # máximo de registros (útil para pruebas rápidas)
        self.advertencias: list[str] = []

    @abstractmethod
    def consultar(self, desde: date, hasta: date) -> list[Registro]:
        """Devuelve los registros publicados entre 'desde' y 'hasta' (ambos incluidos)."""

    def _alcanzo_limite(self, cantidad: int) -> bool:
        return self.limite is not None and cantidad >= self.limite

    def _avisar(self, mensaje: str) -> None:
        self.advertencias.append(mensaje)
        self.log(f"   ! {mensaje}")
