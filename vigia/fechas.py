"""Manejo y validación de rangos de fechas."""

from __future__ import annotations

from datetime import date, timedelta
from typing import Iterator

from vigia.config import MAX_ANIOS


class RangoFechasError(ValueError):
    """Se lanza cuando el rango de fechas no cumple las reglas."""


def restar_anios(fecha: date, anios: int) -> date:
    """Resta años a una fecha. Si cae en 29 de febrero de un año no bisiesto, usa el 28."""
    try:
        return fecha.replace(year=fecha.year - anios)
    except ValueError:
        return fecha.replace(year=fecha.year - anios, day=28)


def fecha_minima_permitida(hoy: date | None = None) -> date:
    """Fecha más antigua que se puede consultar (hoy menos 5 años)."""
    return restar_anios(hoy or date.today(), MAX_ANIOS)


def parsear_fecha(texto: str) -> date:
    """Convierte 'YYYY-MM-DD' en date, con un mensaje de error claro."""
    try:
        return date.fromisoformat(texto.strip())
    except (ValueError, AttributeError):
        raise RangoFechasError(
            f"Fecha inválida: '{texto}'. Usa el formato AAAA-MM-DD (ej. 2024-03-15)."
        ) from None


def validar_rango(desde: date, hasta: date, hoy: date | None = None) -> tuple[date, date]:
    """Verifica que el rango esté dentro de los últimos 5 años y tenga sentido."""
    hoy = hoy or date.today()
    minima = fecha_minima_permitida(hoy)

    if desde > hasta:
        raise RangoFechasError(f"La fecha inicial ({desde}) es posterior a la final ({hasta}).")
    if hasta > hoy:
        raise RangoFechasError(f"La fecha final ({hasta}) no puede estar en el futuro (hoy es {hoy}).")
    if desde < minima:
        raise RangoFechasError(
            f"La fecha inicial ({desde}) está fuera de los últimos {MAX_ANIOS} años. "
            f"La más antigua permitida es {minima}."
        )
    return desde, hasta


def rango_ultimos_dias(dias: int, hoy: date | None = None) -> tuple[date, date]:
    """Rango que termina hoy y empieza 'dias - 1' días atrás (ambos incluidos)."""
    if dias < 1:
        raise RangoFechasError("La cantidad de días debe ser 1 o más.")
    hoy = hoy or date.today()
    return validar_rango(hoy - timedelta(days=dias - 1), hoy, hoy)


def dividir_rango(desde: date, hasta: date, max_dias: int) -> Iterator[tuple[date, date]]:
    """Divide [desde, hasta] en tramos de hasta 'max_dias' días (incluidos ambos extremos).

    Se necesita porque la API de la NVD no acepta rangos mayores a 120 días.
    Ejemplo: 1-ene a 10-ene con max_dias=4 -> (1,4), (5,8), (9,10)
    """
    if max_dias < 1:
        raise ValueError("max_dias debe ser 1 o más")
    inicio = desde
    while inicio <= hasta:
        fin = min(inicio + timedelta(days=max_dias - 1), hasta)
        yield inicio, fin
        inicio = fin + timedelta(days=1)
