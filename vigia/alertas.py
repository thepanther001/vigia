"""Alertas a Discord cuando CISA agrega vulnerabilidades explotadas al catálogo KEV.

Configuración: crear un webhook en el canal de Discord
(Editar canal → Integraciones → Webhooks → Nuevo webhook → Copiar URL)
y guardarlo como variable de entorno / secreto: DISCORD_WEBHOOK_URL.

Seguridad: solo se acepta una URL de webhook oficial de Discord
(https://discord.com/api/webhooks/...). Así, aunque alguien cambie la variable,
el programa no envía datos a un servidor cualquiera.
"""

from __future__ import annotations

import re
from datetime import date, timedelta

import pandas as pd

from vigia.cliente_http import ClienteHTTP, ErrorFuente
from vigia.modelo import FUENTE_KEV

PATRON_WEBHOOK = re.compile(r"^https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[\w-]+$")
MAX_ALERTAS = 10  # Discord acepta hasta 10 "embeds" por mensaje

COLORES = {"INMEDIATA": 0xD03B3B, "URGENTE": 0xEC835A, "PLANIFICADA": 0xFAB219, "RUTINA": 0x898781}


class ErrorAlerta(ValueError):
    pass


def validar_webhook(url: str | None) -> str:
    if not url:
        raise ErrorAlerta("Falta DISCORD_WEBHOOK_URL (variable de entorno o secreto de GitHub).")
    url = url.strip()
    if not PATRON_WEBHOOK.match(url):
        raise ErrorAlerta("DISCORD_WEBHOOK_URL no parece un webhook de Discord (https://discord.com/api/webhooks/...).")
    return url


def nuevas_en_kev(registros: pd.DataFrame, consolidado: pd.DataFrame, dias: int, hoy: date | None = None) -> pd.DataFrame:
    """CVE que CISA agregó al catálogo KEV en los últimos 'dias' días, ordenadas por prioridad."""
    hoy = hoy or date.today()
    desde = pd.Timestamp(hoy - timedelta(days=dias))
    kev = registros[(registros["fuente"] == FUENTE_KEV) & (registros["fecha_publicacion"] >= desde)]
    if kev.empty:
        return consolidado.head(0)
    agregadas = kev.set_index("cve_id")["fecha_publicacion"]
    datos = consolidado[consolidado["cve_id"].isin(agregadas.index)].copy()
    datos["fecha_kev"] = datos["cve_id"].map(agregadas)
    return datos.sort_values("prioridad_puntaje", ascending=False)


def _recortar(texto, largo: int) -> str:
    texto = " ".join(str(texto or "").split())
    return texto if len(texto) <= largo else texto[: largo - 1] + "…"


def _sin_menciones(texto: str) -> str:
    """Evita que un texto externo haga @everyone/@here en el servidor."""
    return texto.replace("@", "@​")


def construir_mensaje(nuevas: pd.DataFrame, url_panel: str | None = None) -> dict:
    total = len(nuevas)
    embeds = []
    for r in nuevas.head(MAX_ALERTAS).itertuples(index=False):
        campos = [
            {"name": "Prioridad", "value": f"{r.prioridad_nivel} · {r.prioridad_puntaje:g}/100", "inline": True},
            {"name": "CVSS", "value": "—" if pd.isna(r.cvss_puntaje) else f"{r.cvss_puntaje:.1f} {r.severidad}", "inline": True},
            {"name": "Ransomware", "value": "Sí" if r.ransomware == "Sí" else "No confirmado", "inline": True},
        ]
        if getattr(r, "epss", None) is not None and not pd.isna(getattr(r, "epss", None)):
            campos.append({"name": "EPSS (30 días)", "value": f"{r.epss * 100:.1f}%", "inline": True})
        if not pd.isna(r.fecha_limite_cisa):
            campos.append({"name": "Fecha límite CISA", "value": pd.Timestamp(r.fecha_limite_cisa).strftime("%Y-%m-%d"), "inline": True})
        if getattr(r, "activos_afectados", None):
            campos.append({"name": "⚠ Afecta a tu inventario", "value": _recortar(r.activos_afectados, 200), "inline": False})
        embeds.append({
            "title": _sin_menciones(_recortar(f"{r.cve_id} — {r.titulo or ''}", 250)),
            "url": f"https://nvd.nist.gov/vuln/detail/{r.cve_id}",
            "description": _sin_menciones(_recortar(r.descripcion, 300)),
            "color": COLORES.get(r.prioridad_nivel, 0x898781),
            "fields": campos,
            "footer": {"text": f"{r.proveedor or ''} · {r.producto or ''}".strip(" ·")},
        })
    encabezado = f"🚨 **{total} vulnerabilidad{'es' if total != 1 else ''} nueva{'s' if total != 1 else ''} explotada{'s' if total != 1 else ''} activamente** (CISA KEV)"
    if total > MAX_ALERTAS:
        encabezado += f" — se muestran las {MAX_ALERTAS} de mayor prioridad"
    if url_panel:
        encabezado += f"\nPanel completo: {url_panel}"
    return {
        "username": "Vigía",
        "content": encabezado,
        "embeds": embeds,
        "allowed_mentions": {"parse": []},  # nunca notificar a @everyone / roles
    }


class ClienteDiscord(ClienteHTTP):
    nombre = "Discord"

    def enviar(self, webhook: str, mensaje: dict) -> None:
        url = validar_webhook(webhook)
        for intento in range(3):
            resp = self.sesion.post(url, json=mensaje, timeout=30)
            if resp.status_code in (200, 204):
                return
            if resp.status_code == 429:
                espera = float((resp.json() or {}).get("retry_after", 2))
                self._esperar(espera)
                continue
            raise ErrorFuente(f"Discord: HTTP {resp.status_code} — {(resp.text or '')[:150]}", resp.status_code)
        raise ErrorFuente("Discord: límite de velocidad, no se pudo enviar.")
