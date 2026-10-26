"""Pruebas de prioridad, inventario, panel web y alertas."""

import json
import re
from datetime import date

import pytest

from conftest import cargar
from vigia import alertas, dashboard, inventario as inv, prioridad
from vigia import procesamiento as proc
from vigia.fuentes.cisa_kev import parsear_kev
from vigia.fuentes.github_advisory import parsear_advisory
from vigia.fuentes.nvd import parsear_cve

DESDE, HASTA = date(2025, 1, 1), date(2025, 3, 31)


@pytest.fixture
def datos():
    nvd = [parsear_cve(v["cve"]) for v in cargar("nvd_pagina.json")["vulnerabilities"]]
    ghsa = [r for r in (parsear_advisory(a) for a in cargar("ghsa_pagina.json")) if r]
    kev = [parsear_kev(v) for v in cargar("kev.json")["vulnerabilities"] if v["dateAdded"] >= "2025-01-01"]
    registros = proc.registros_a_df(nvd + ghsa + kev)
    consolidado = proc.consolidar(registros)
    consolidado = proc.agregar_epss(consolidado, {"CVE-2025-0001": (0.94, 0.999), "CVE-2025-0004": (0.02, 0.80)})
    return registros, prioridad.agregar_prioridad(consolidado)


def fila(df, cve):
    return df.set_index("cve_id").loc[cve]


# ---------------------------------------------------------------- prioridad

def test_formula_y_topes():
    puntaje, motivos = prioridad.calcular(9.8, 0.999, en_kev=True, ransomware=True)
    assert puntaje == 99.2                        # 39.2 + 24.975 + 25 + 10 = 99.175 -> 99.2
    assert "Usada en ransomware" in motivos
    assert prioridad.calcular(10, 1.0, en_kev=True, ransomware=True)[0] == 100.0  # máximo posible


def test_formula_exacta():
    assert prioridad.calcular(5.0, 0.5)[0] == 32.5          # 20 + 12.5
    assert prioridad.calcular(None, None, en_kev=True)[0] == 60.0  # piso KEV
    assert prioridad.calcular(None, None, en_kev=True, ransomware=True)[0] == 80.0
    assert prioridad.calcular(9.1, None)[0] == 40.0          # piso CVSS crítico
    assert prioridad.calcular(2.0, 0.1)[0] == 10.5


def test_niveles():
    assert prioridad.nivel_de(85)[0] == "INMEDIATA"
    assert prioridad.nivel_de(60)[0] == "URGENTE"
    assert prioridad.nivel_de(59.9)[0] == "PLANIFICADA"
    assert prioridad.nivel_de(0)[0] == "RUTINA"


def test_prioridad_en_consolidado(datos):
    _, c = datos
    a = fila(c, "CVE-2025-0001")                  # KEV + ransomware + CVSS 9.8 + EPSS p99.9
    assert a["prioridad_nivel"] == "INMEDIATA" and a["prioridad_puntaje"] >= 95
    assert prioridad.top_prioridad(c, 1)["cve_id"].iat[0] == "CVE-2025-0001"
    assert prioridad.resumen_niveles(c)["CVE"].sum() == len(c)


# ---------------------------------------------------------------- inventario

def test_coincidencias():
    a = inv.Activo("DC", "Microsoft", "Windows Server")
    assert inv.coincide(a, "Microsoft", "windows server 2019, windows 10")
    assert inv.coincide(a, "microsoft", "Windows")                 # KEV dice solo "Windows"
    assert not inv.coincide(a, "Microsoft", "Exchange Server")
    assert not inv.coincide(a, "Apple", "Windows Server")
    pa = inv.Activo("FW", "Palo Alto Networks", "PAN-OS")
    assert inv.coincide(pa, "Paloaltonetworks", "pan-os")            # nombres escritos distinto
    assert not inv.coincide(a, None, None)


def test_cargar_inventario(tmp_path):
    ruta = tmp_path / "inv.csv"
    ruta.write_text("activo,proveedor,producto,version,criticidad\nWeb,Example Corp,Web Server,1.0,alta\n,,\n",
                    encoding="utf-8")
    activos = inv.cargar(ruta)
    assert activos == [inv.Activo("Web", "Example Corp", "Web Server", "1.0", "Alta")]
    malo = tmp_path / "malo.csv"
    malo.write_text("nombre,otra\nx,y\n", encoding="utf-8")
    with pytest.raises(inv.InventarioError):
        inv.cargar(malo)


def test_inventario_de_ejemplo_es_valido():
    assert len(inv.cargar("inventario/empresa_ejemplo.csv")) >= 10


def test_cruce(datos):
    _, c = datos
    activos = [inv.Activo("Servidor web", "Example Corp", "Web Server", criticidad="Alta"),
               inv.Activo("Correo", "Microsoft", "Exchange Server")]
    c2, afect = inv.cruzar(c, activos)
    assert fila(c2, "CVE-2025-0001")["activos_afectados"] == "Servidor web"
    assert set(afect["cve_id"]) == {"CVE-2025-0001"}
    resumen = inv.resumen_por_activo(afect, activos)
    assert resumen.set_index("activo").loc["Correo", "CVE"] == 0


# ---------------------------------------------------------------- panel web

def test_dashboard_escapa_datos_y_csp(datos, tmp_path):
    registros, c = datos
    c = c.copy()
    c.loc[0, "titulo"] = "</script><script>alert(1)</script>"   # dato malicioso
    resumenes = {
        "por_severidad": proc.tabla_por_severidad(c),
        "top_proveedores": proc.tabla_top_proveedores(c),
        "top_cwe": proc.tabla_top_cwe(c),
    }
    kpis = proc.indicadores(c, registros)
    d = dashboard.construir_datos(registros, c, resumenes, kpis, DESDE, HASTA,
                                  ["NVD", "CISA KEV", "GitHub Advisory"], {}, None, {})
    ruta = dashboard.generar(tmp_path / "panel", d, [])
    html = ruta.read_text(encoding="utf-8")

    assert "<script>alert(1)" not in html                      # no se puede inyectar
    bloque = re.search(r'<script type="application/json" id="datos">(.*?)</script>', html, re.S).group(1)
    assert json.loads(bloque)["total_cves"] == len(c)          # pero el JSON sigue siendo válido
    script = re.findall(r"<script>(.*?)</script>", html, re.S)[-1]
    assert dashboard._hash_csp(script) in html                 # el hash CSP coincide con el script
    assert "<script src=" not in html                          # sin scripts de terceros
    assert (tmp_path / "panel" / ".nojekyll").exists()


def test_serie_diaria_y_mensual(datos):
    registros, _ = datos
    assert proc.serie_temporal(registros, DESDE, HASTA)["granularidad"] == "día"
    larga = proc.serie_temporal(registros, date(2024, 1, 1), HASTA)
    assert larga["granularidad"] == "mes" and larga["etiquetas"][0] == "2024-01"


# ---------------------------------------------------------------- alertas

def test_validar_webhook():
    assert alertas.validar_webhook("https://discord.com/api/webhooks/123/abc-DEF_1")
    for malo in (None, "", "http://discord.com/api/webhooks/1/a", "https://evil.com/api/webhooks/1/a",
                 "https://discord.com.evil.com/api/webhooks/1/a"):
        with pytest.raises(alertas.ErrorAlerta):
            alertas.validar_webhook(malo)


def test_mensaje_discord(datos):
    registros, c = datos
    nuevas = alertas.nuevas_en_kev(registros, c, dias=30, hoy=date(2025, 2, 25))
    assert list(nuevas["cve_id"]) == ["CVE-2024-5555"]          # CVE-2025-0001 se agregó en enero
    c.loc[c["cve_id"] == "CVE-2024-5555", "titulo"] = "Falla @everyone"
    nuevas = alertas.nuevas_en_kev(registros, c, dias=30, hoy=date(2025, 2, 25))
    msg = alertas.construir_mensaje(nuevas, "https://ejemplo.github.io/vigia/")
    assert msg["allowed_mentions"] == {"parse": []}
    assert "@everyone" not in msg["embeds"][0]["title"]
    assert "1 vulnerabilidad nueva explotada" in msg["content"]
