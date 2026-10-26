from datetime import date

import pytest

from vigia.fechas import (
    RangoFechasError,
    dividir_rango,
    fecha_minima_permitida,
    parsear_fecha,
    rango_ultimos_dias,
    restar_anios,
    validar_rango,
)

HOY = date(2026, 10, 22)


def test_fecha_minima_es_cinco_anios_atras():
    assert fecha_minima_permitida(HOY) == date(2021, 10, 22)


def test_restar_anios_29_febrero():
    assert restar_anios(date(2028, 2, 29), 5) == date(2023, 2, 28)


def test_rango_valido():
    assert validar_rango(date(2024, 1, 1), date(2024, 12, 31), HOY) == (date(2024, 1, 1), date(2024, 12, 31))


def test_limite_exacto_de_cinco_anios_es_valido():
    validar_rango(date(2021, 10, 22), HOY, HOY)


@pytest.mark.parametrize(
    "desde, hasta",
    [
        (date(2021, 10, 21), date(2022, 1, 1)),  # más de 5 años
        (date(2025, 5, 1), date(2025, 4, 1)),    # invertido
        (date(2026, 10, 1), date(2026, 10, 23)), # en el futuro
    ],
)
def test_rangos_invalidos(desde, hasta):
    with pytest.raises(RangoFechasError):
        validar_rango(desde, hasta, HOY)


def test_parsear_fecha_invalida():
    with pytest.raises(RangoFechasError):
        parsear_fecha("22/10/2026")


def test_ultimos_dias():
    assert rango_ultimos_dias(30, HOY) == (date(2026, 9, 23), HOY)
    with pytest.raises(RangoFechasError):
        rango_ultimos_dias(3000, HOY)


def test_dividir_rango_cubre_todo_sin_huecos():
    tramos = list(dividir_rango(date(2024, 1, 1), date(2024, 12, 31), 120))
    assert tramos[0][0] == date(2024, 1, 1)
    assert tramos[-1][1] == date(2024, 12, 31)
    assert all((fin - ini).days < 120 for ini, fin in tramos)
    for (_, fin), (ini_sig, _) in zip(tramos, tramos[1:]):
        assert (ini_sig - fin).days == 1


def test_dividir_rango_un_dia():
    assert list(dividir_rango(date(2025, 1, 1), date(2025, 1, 1), 120)) == [(date(2025, 1, 1), date(2025, 1, 1))]
