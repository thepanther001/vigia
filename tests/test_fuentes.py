from datetime import date

import pytest

from conftest import RespuestaFalsa, SesionFalsa, cargar, sin_esperas
from vigia.cliente_http import ErrorFuente
from vigia.fuentes.cisa_kev import FuenteCISAKEV
from vigia.fuentes.github_advisory import FuenteGitHub, parsear_advisory
from vigia.fuentes.nvd import FuenteNVD, parsear_cve

# ---------------------------------------------------------------- NVD


def test_nvd_prefiere_metrica_primary_y_descripcion_en_espanol():
    cve = cargar("nvd_pagina.json")["vulnerabilities"][0]["cve"]
    r = parsear_cve(cve, idioma="es")
    assert r.cvss_puntaje == 9.8
    assert r.severidad == "CRÍTICA"
    assert r.cvss_version == "3.1"
    assert r.descripcion.startswith("Vulnerabilidad de ejecución remota")
    assert r.cwe == "CWE-78; CWE-20"
    assert r.proveedor == "Example Corp"
    assert r.producto == "web server, admin panel"
    assert r.explotada_activamente is True
    assert r.fecha_publicacion == date(2025, 1, 5)


def test_nvd_cvss_v2_y_cwe_noinfo():
    cve = cargar("nvd_pagina.json")["vulnerabilities"][1]["cve"]
    r = parsear_cve(cve)
    assert (r.cvss_puntaje, r.cvss_version, r.severidad) == (7.5, "2.0", "ALTA")
    assert r.cwe is None
    assert r.descripcion.startswith("=cmd")  # en inglés porque no hay español
    assert r.explotada_activamente is None


def test_nvd_sin_metricas():
    r = parsear_cve(cargar("nvd_pagina.json")["vulnerabilities"][2]["cve"])
    assert r.cvss_puntaje is None and r.severidad is None


def test_nvd_consulta_divide_en_tramos(silencio):
    pagina = cargar("nvd_pagina.json")
    vacia = {"resultsPerPage": 0, "startIndex": 0, "totalResults": 0, "vulnerabilities": []}
    sesion = SesionFalsa([RespuestaFalsa(pagina), RespuestaFalsa(vacia)])
    fuente = sin_esperas(FuenteNVD(sesion=sesion, log=silencio))
    registros = fuente.consultar(date(2025, 1, 1), date(2025, 6, 30))  # 181 días -> 2 tramos
    assert len(registros) == 3
    assert len(sesion.solicitudes) == 2
    assert "noRejected" in sesion.solicitudes[0]["url"]
    assert "pubStartDate=2025-05-01" in sesion.solicitudes[1]["url"]


def test_nvd_reintenta_si_hay_limite(silencio):
    sesion = SesionFalsa([RespuestaFalsa(status_code=403, text="rate"), RespuestaFalsa(cargar("nvd_pagina.json"))])
    fuente = sin_esperas(FuenteNVD(sesion=sesion, log=silencio))
    assert len(fuente.consultar(date(2025, 1, 1), date(2025, 1, 31))) == 3


def test_nvd_respeta_limite(silencio):
    sesion = SesionFalsa([RespuestaFalsa(cargar("nvd_pagina.json"))])
    fuente = sin_esperas(FuenteNVD(sesion=sesion, log=silencio, limite=2))
    assert len(fuente.consultar(date(2025, 1, 1), date(2025, 1, 31))) == 2


# ---------------------------------------------------------------- GitHub


def test_ghsa_parseo():
    avisos = cargar("ghsa_pagina.json")
    r = parsear_advisory(avisos[0])
    assert r.cve_id == "CVE-2025-0003" and r.id_fuente == "GHSA-aaaa-bbbb-cccc"
    assert r.severidad == "MEDIA"            # "moderate"
    assert r.cvss_puntaje == 5.6             # v4 con puntaje 0 se ignora
    assert r.ecosistema == "npm"
    r4 = parsear_advisory(avisos[2])
    assert (r4.cvss_puntaje, r4.cvss_version) == (9.3, "4.0")
    assert r4.producto == "org.example:java-lib, org.example:java-lib-core"


def test_ghsa_sin_cve_se_omite_por_defecto():
    aviso = cargar("ghsa_pagina.json")[1]
    assert parsear_advisory(aviso) is None
    assert parsear_advisory(aviso, incluir_sin_cve=True).cve_id == "GHSA-dddd-eeee-ffff"


def test_ghsa_paginacion_y_token(silencio):
    avisos = cargar("ghsa_pagina.json")
    sesion = SesionFalsa([
        RespuestaFalsa(avisos[:2], links={"next": {"url": "https://api.github.com/advisories?after=X"}}),
        RespuestaFalsa(avisos[2:]),
    ])
    fuente = sin_esperas(FuenteGitHub(token="abc", sesion=sesion, log=silencio))
    registros = fuente.consultar(date(2025, 3, 1), date(2025, 3, 31))
    assert [r.cve_id for r in registros] == ["CVE-2025-0003", "CVE-2025-0004"]
    assert sesion.solicitudes[0]["params"]["published"] == "2025-03-01..2025-03-31"
    assert sesion.solicitudes[0]["headers"]["Authorization"] == "Bearer abc"
    assert sesion.solicitudes[1]["params"] is None


def test_ghsa_cuota_agotada_entrega_parcial(silencio):
    import time

    avisos = cargar("ghsa_pagina.json")
    agotado = RespuestaFalsa(status_code=403, headers={
        "X-RateLimit-Remaining": "0", "X-RateLimit-Reset": str(int(time.time()) + 3600)})
    sesion = SesionFalsa([
        RespuestaFalsa(avisos[:1], links={"next": {"url": "https://api.github.com/advisories?after=X"}}),
        agotado,
    ])
    fuente = sin_esperas(FuenteGitHub(sesion=sesion, log=silencio))
    registros = fuente.consultar(date(2025, 3, 1), date(2025, 3, 31))
    assert len(registros) == 1
    assert fuente.advertencias and "cuota" in fuente.advertencias[0]


# ---------------------------------------------------------------- CISA KEV


def test_kev_filtra_por_fecha_agregada(silencio):
    sesion = SesionFalsa([RespuestaFalsa(cargar("kev.json"))])
    fuente = sin_esperas(FuenteCISAKEV(sesion=sesion, log=silencio))
    registros = fuente.consultar(date(2025, 1, 1), date(2025, 3, 31))
    assert [r.cve_id for r in registros] == ["CVE-2025-0001", "CVE-2024-5555"]
    assert registros[0].ransomware == "Sí" and registros[1].ransomware == "Desconocido"
    assert all(r.explotada_activamente for r in registros)


def test_kev_usa_espejo_si_falla_el_principal(silencio):
    sesion = SesionFalsa([RespuestaFalsa(status_code=404, text="no"), RespuestaFalsa(cargar("kev.json"))])
    fuente = sin_esperas(FuenteCISAKEV(sesion=sesion, log=silencio))
    assert len(fuente.consultar(date(2025, 1, 1), date(2025, 3, 31))) == 2
    assert "githubusercontent" in sesion.solicitudes[1]["url"]


def test_error_http_no_reintentable(silencio):
    sesion = SesionFalsa([RespuestaFalsa(status_code=404, text="x"), RespuestaFalsa(status_code=404, text="x")])
    fuente = sin_esperas(FuenteCISAKEV(sesion=sesion, log=silencio))
    with pytest.raises(ErrorFuente):
        fuente.consultar(date(2025, 1, 1), date(2025, 3, 31))
