"use strict";
(function () {
  const D = JSON.parse(document.getElementById("datos").textContent);
  const $ = (s) => document.querySelector(s);

  // ---------- utilidades (todo el texto se pinta con textContent: nada de innerHTML con datos)
  function el(tag, attrs, ...hijos) {
    const e = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v == null || v === false) continue;
      if (k === "class") e.className = v;
      else if (k === "text") e.textContent = v;
      else if (k === "style") e.style.cssText = v;
      else e.setAttribute(k, v);
    }
    for (const h of hijos) {
      if (h == null || h === false) continue;
      e.append(h.nodeType ? h : document.createTextNode(String(h)));
    }
    return e;
  }
  const fmt = (n, d = 0) =>
    n == null ? "—" : Number(n).toLocaleString("es-DO", { minimumFractionDigits: d, maximumFractionDigits: d });
  const css = (v) => getComputedStyle(document.documentElement).getPropertyValue(v).trim();
  function urlSegura(u) {
    try {
      const x = new URL(u);
      return x.protocol === "https:" || x.protocol === "http:" ? x.href : null;
    } catch (_) { return null; }
  }
  function fechaLarga(iso) {
    const [y, m, d] = iso.split("-").map(Number);
    return new Date(y, m - 1, d).toLocaleDateString("es-DO", { day: "numeric", month: "short", year: "numeric" });
  }

  const COLOR_SEV = {
    "CRÍTICA": "--critical", "ALTA": "--serious", "MEDIA": "--warning",
    "BAJA": "--good", "NINGUNA": "--neutral", "SIN CALIFICAR": "--neutral",
  };
  const COLOR_NIVEL = { INMEDIATA: "--critical", URGENTE: "--serious", PLANIFICADA: "--warning", RUTINA: "--neutral" };
  const COLOR_FUENTE = { "NVD": "--s1", "CISA KEV": "--s2", "GitHub Advisory": "--s3" };
  const TINTA_OSCURA = new Set(["--warning"]);  // texto negro sobre amarillo

  function chip(texto, varColor, clase) {
    if (!texto) return null;
    const c = el("span", { class: "chip " + clase + (TINTA_OSCURA.has(varColor) ? " dark-ink" : ""), text: texto });
    c.style.background = `var(${varColor})`;
    return c;
  }
  const chipSev = (s) => chip(s, COLOR_SEV[s] || "--neutral", "sev");
  const chipNivel = (n) => chip(n, COLOR_NIVEL[n] || "--neutral", "niv");

  // ---------- tema claro / oscuro
  const raiz = document.documentElement;
  try { const t = localStorage.getItem("tema"); if (t) raiz.dataset.theme = t; } catch (_) {}
  function temaActual() {
    return raiz.dataset.theme || (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
  }
  function etiquetaTema() { $("#tema").textContent = temaActual() === "dark" ? "☀ Claro" : "☾ Oscuro"; }
  $("#tema").addEventListener("click", () => {
    raiz.dataset.theme = temaActual() === "dark" ? "light" : "dark";
    try { localStorage.setItem("tema", raiz.dataset.theme); } catch (_) {}
    etiquetaTema();
    dibujarGraficos();
  });
  etiquetaTema();

  // ---------- encabezado
  const m = D.meta;
  const generado = new Date(m.generado);
  const horas = (Date.now() - generado.getTime()) / 36e5;
  const hace = horas < 1 ? "hace menos de 1 hora" : horas < 48 ? `hace ${Math.round(horas)} h` : `hace ${Math.round(horas / 24)} días`;
  $("#actualizado").textContent =
    "Actualizado " + generado.toLocaleString("es-DO", { dateStyle: "medium", timeStyle: "short" }) + " · " + hace;
  if (horas > 36) $("#pulso").classList.add("viejo");

  $("#bajada").textContent =
    `${fmt(D.kpis.total)} vulnerabilidades del ${fechaLarga(m.desde)} al ${fechaLarga(m.hasta)}, ` +
    `consolidadas de ${m.fuentes.length} ${m.fuentes.length === 1 ? "base de datos" : "bases de datos"} y ordenadas por lo que hay que corregir primero.`;
  for (const f of m.fuentes) {
    const estado = (m.estado || {})[f] || "";
    const error = estado.startsWith("ERROR");
    const pill = el("span", { class: "src" + (error ? " err" : ""), title: estado },
      el("i", { style: `background:var(${COLOR_FUENTE[f] || "--neutral"})` }), f + (error ? " — sin datos" : ""));
    $("#fuentes").append(pill);
  }
  if (D.cves.some((c) => c.epss != null)) {
    $("#fuentes").append(el("span", { class: "src", title: "Probabilidad de explotación (FIRST.org)" },
      el("i", { style: "background:var(--neutral)" }), "+ EPSS"));
  }

  // ---------- indicadores
  const K = D.kpis;
  const tarjetas = [
    ["CVE en el periodo", K.total, `CVSS promedio ${fmt(K.cvss_prom, 1)}`, "--s1"],
    ["Críticas", K.criticas, `${fmt(K.altas)} ${K.altas === 1 ? "alta" : "altas"}`, "--critical"],
    ["Explotadas activamente", K.explotadas, "en el catálogo CISA KEV", "--s2"],
    ["Usadas en ransomware", K.ransomware, "según CISA", "--critical"],
    ["Prioridad inmediata", K.inmediata, `${fmt(K.urgente)} ${K.urgente === 1 ? "urgente" : "urgentes"}`, "--serious"],
  ];
  if (D.inventario) {
    tarjetas.push(["Afectan mi inventario", D.inventario.total_cve,
      `${D.inventario.total_afectados} de ${D.inventario.activos.length} activos`, "--accent"]);
  } else {
    tarjetas.push(["Proveedores distintos", D.proveedores.length ? D.proveedores.length + "+" : 0, "top en el periodo", "--s3"]);
  }
  for (const [lbl, val, nota, color] of tarjetas) {
    $("#kpis").append(el("div", { class: "card kpi" },
      el("div", { class: "lbl" }, el("i", { style: `background:var(${color})` }), lbl),
      el("div", { class: "val", text: typeof val === "number" ? fmt(val) : val }),
      el("div", { class: "nota", text: nota })));
  }

  // ---------- Top 10
  function enlaceCve(c) {
    const u = urlSegura(c.url);
    return u ? el("a", { class: "cveid", href: u, target: "_blank", rel: "noopener noreferrer", text: c.id })
             : el("span", { class: "cveid", text: c.id });
  }
  const top = D.cves.slice(0, 10);
  if (!top.length) $("#top10").append(el("li", {}, el("span"), el("span", { text: "Sin datos en el periodo." })));
  top.forEach((c, i) => {
    const producto = [c.prov, c.prod].filter(Boolean).join(" · ");
    const barra = el("span");
    barra.style.width = (c.puntaje || 0) + "%";
    barra.style.background = `var(${COLOR_NIVEL[c.nivel] || "--neutral"})`;
    $("#top10").append(el("li", {},
      el("div", { class: "rank", text: i + 1 }),
      el("div", {},
        el("div", { class: "meta-line" }, enlaceCve(c), chipSev(c.sev),
          c.kev ? el("span", { class: "chip kev", text: "Explotada" }) : null,
          c.rans ? el("span", { class: "chip rans", text: "Ransomware" }) : null,
          c.activos ? el("span", { class: "chip inv", text: "Afecta: " + c.activos }) : null),
        el("div", { class: "tt", text: c.titulo || "" }),
        el("div", { class: "meta-line", text: producto }),
        el("div", { class: "motivo", text: c.motivo || "" })),
      el("div", { class: "score" },
        el("div", { class: "num" }, el("span", {}, chipNivel(c.nivel)), el("b", { text: fmt(c.puntaje) })),
        el("div", { class: "bar" }, barra),
        el("div", { class: "sub", text: "Corregir en: " + (c.plazo || "—") }))));
  });

  // ---------- Inventario
  if (D.inventario) {
    $("#sec-inv").hidden = false;
    const inv = D.inventario;
    $("#inv-sub").textContent = `${inv.nombre} · coincidencia por proveedor y producto (verificar versión con el fabricante)`;
    const t = $("#tabla-inv");
    t.append(el("thead", {}, el("tr", {},
      el("th", { text: "Activo" }), el("th", { text: "Software" }), el("th", { text: "Criticidad" }),
      el("th", { class: "num", text: "CVE" }), el("th", { class: "num", text: "Explotadas" }),
      el("th", { text: "Prioridad máx." }))));
    const tb = el("tbody");
    for (const a of inv.activos) {
      const nivel = a.prioridad_max == null ? null
        : a.prioridad_max >= 80 ? "INMEDIATA" : a.prioridad_max >= 60 ? "URGENTE" : a.prioridad_max >= 40 ? "PLANIFICADA" : "RUTINA";
      tb.append(el("tr", {},
        el("td", { text: a.activo }), el("td", { text: a.producto }), el("td", { text: a.criticidad }),
        el("td", { class: "num", text: fmt(a.cve) }), el("td", { class: "num", text: fmt(a.explotadas) }),
        el("td", {}, a.cve ? el("span", {}, chipNivel(nivel), " ", fmt(a.prioridad_max))
                           : el("span", { class: "ok", text: "✓ Sin hallazgos" }))));
    }
    t.append(tb);
  } else {
    $("#lbl-inv").hidden = true;
  }

  // ---------- Gráficos
  const graficos = {};
  function ejes(horizontal) {
    const g = { color: css("--grid") }, t = { color: css("--muted"), font: { size: 11 } };
    const valor = { beginAtZero: true, grid: g, border: { display: false }, ticks: { ...t, precision: 0 } };
    const cat = { grid: { display: false }, border: { color: css("--axis") }, ticks: t };
    return horizontal ? { x: valor, y: { ...cat, ticks: { ...t, color: css("--ink-2"), font: { size: 12 } } } } : { x: cat, y: valor };
  }
  const tooltip = () => ({
    backgroundColor: css("--surface"), titleColor: css("--ink"), bodyColor: css("--ink-2"),
    borderColor: css("--ring"), borderWidth: 1, padding: 10, boxPadding: 4, usePointStyle: true,
  });
  function barras(id, etiquetas, valores, colores) {
    graficos[id] = new Chart(document.getElementById(id), {
      type: "bar",
      data: { labels: etiquetas, datasets: [{ data: valores, backgroundColor: colores, borderRadius: 4, borderSkipped: "start", maxBarThickness: 22 }] },
      options: {
        indexAxis: "y", responsive: true, maintainAspectRatio: false, animation: false,
        plugins: { legend: { display: false }, tooltip: tooltip() }, scales: ejes(true),
      },
    });
  }
  function dibujarGraficos() {
    if (typeof Chart === "undefined") { document.body.classList.add("no-charts"); return; }
    Object.values(graficos).forEach((g) => g.destroy());

    // Tendencia por fuente
    const s = D.serie;
    const nombres = Object.keys(s.series);
    const leyenda = $("#leg-serie");
    leyenda.replaceChildren(...nombres.map((n) =>
      el("span", {}, el("i", { style: `background:var(${COLOR_FUENTE[n]})` }), n)));
    graficos.serie = new Chart(document.getElementById("g-serie"), {
      type: "line",
      data: {
        labels: s.etiquetas.map((e) => (s.granularidad === "día" ? e.slice(5) : e)),
        datasets: nombres.map((n) => ({
          label: n, data: s.series[n], borderColor: css(COLOR_FUENTE[n]), backgroundColor: css(COLOR_FUENTE[n]),
          borderWidth: 2, pointRadius: 0, pointHoverRadius: 5, pointHoverBorderWidth: 2,
          pointHoverBorderColor: css("--surface"), tension: 0,
        })),
      },
      options: {
        responsive: true, maintainAspectRatio: false, animation: false,
        interaction: { mode: "index", intersect: false },
        plugins: { legend: { display: false }, tooltip: tooltip() },
        scales: { ...ejes(false), x: { ...ejes(false).x, ticks: { ...ejes(false).x.ticks, maxTicksLimit: 10, maxRotation: 0 } } },
      },
    });

    barras("g-niveles", D.niveles.map((n) => `${n.nivel} · ${n.plazo}`), D.niveles.map((n) => n.cve),
      D.niveles.map((n) => css(COLOR_NIVEL[n.nivel])));
    const sevs = Object.keys(D.severidad).filter((k) => D.severidad[k] > 0 || ["CRÍTICA", "ALTA", "MEDIA", "BAJA"].includes(k));
    barras("g-sev", sevs, sevs.map((k) => D.severidad[k]), sevs.map((k) => css(COLOR_SEV[k])));
    barras("g-prov", D.proveedores.map((p) => p.nombre), D.proveedores.map((p) => p.cve),
      D.proveedores.map(() => css("--s1")));
  }
  dibujarGraficos();
  matchMedia("(prefers-color-scheme: dark)").addEventListener("change", () => { etiquetaTema(); dibujarGraficos(); });

  // ---------- Explorador
  const POR_PAGINA = 25;
  let pagina = 0;
  for (const n of D.niveles) $("#f-nivel").append(el("option", { value: n.nivel, text: n.nivel }));
  for (const s of Object.keys(D.severidad)) $("#f-sev").append(el("option", { value: s, text: s }));
  const indice = D.cves.map((c) =>
    [c.id, c.titulo, c.prov, c.prod, c.eco, c.motivo, c.activos].filter(Boolean).join(" ").toLowerCase());

  function filtrados() {
    const q = $("#f-texto").value.trim().toLowerCase();
    const niv = $("#f-nivel").value, sev = $("#f-sev").value;
    const kev = $("#f-kev").checked, inv = $("#f-inv").checked;
    return D.cves.filter((c, i) =>
      (!q || indice[i].includes(q)) && (!niv || c.nivel === niv) && (!sev || c.sev === sev) &&
      (!kev || c.kev) && (!inv || c.activos));
  }
  const tabla = $("#tabla-cve");
  tabla.append(el("thead", {}, el("tr", {},
    el("th", { text: "Prioridad" }), el("th", { text: "CVE" }), el("th", { text: "Título / producto" }),
    el("th", { text: "Severidad" }), el("th", { class: "num", text: "CVSS" }), el("th", { class: "num", text: "EPSS" }),
    el("th", { text: "Fecha" }), el("th", { text: "Fuentes" }))));
  const cuerpo = el("tbody");
  tabla.append(cuerpo);

  function pintarTabla() {
    const lista = filtrados();
    const paginas = Math.max(1, Math.ceil(lista.length / POR_PAGINA));
    pagina = Math.min(pagina, paginas - 1);
    const visibles = lista.slice(pagina * POR_PAGINA, (pagina + 1) * POR_PAGINA);
    cuerpo.replaceChildren(...visibles.map((c) => el("tr", {},
      el("td", {}, chipNivel(c.nivel), el("span", { class: "peq", text: fmt(c.puntaje) + " / 100" })),
      el("td", {}, enlaceCve(c), c.kev ? el("span", { class: "peq", text: "Explotada" + (c.rans ? " · ransomware" : "") }) : null),
      el("td", {}, el("span", { text: c.titulo || "" }),
        el("span", { class: "peq", text: [c.prov, c.prod, c.eco].filter(Boolean).join(" · ") }),
        c.activos ? el("span", { class: "peq", text: "Afecta: " + c.activos }) : null),
      el("td", {}, chipSev(c.sev)),
      el("td", { class: "num", text: fmt(c.cvss, 1) }),
      el("td", { class: "num", text: c.epss == null ? "—" : fmt(c.epss * 100, 1) + "%" }),
      el("td", { text: c.fecha || "—" }),
      el("td", { text: c.fuentes || "" }))));
    if (!visibles.length) cuerpo.append(el("tr", {}, el("td", { colspan: 8, text: "No hay CVE con esos filtros." })));
    $("#pag-info").textContent = lista.length
      ? `${fmt(pagina * POR_PAGINA + 1)}–${fmt(pagina * POR_PAGINA + visibles.length)} de ${fmt(lista.length)}`
      : "0 resultados";
    $("#pag-ant").disabled = pagina === 0;
    $("#pag-sig").disabled = pagina >= paginas - 1;
  }
  for (const id of ["#f-texto", "#f-nivel", "#f-sev", "#f-kev", "#f-inv"]) {
    $(id).addEventListener("input", () => { pagina = 0; pintarTabla(); });
  }
  $("#pag-ant").addEventListener("click", () => { pagina--; pintarTabla(); });
  $("#pag-sig").addEventListener("click", () => { pagina++; pintarTabla(); });
  $("#exp-sub").textContent = D.total_cves > D.cves.length
    ? `las ${fmt(D.cves.length)} de mayor prioridad (de ${fmt(D.total_cves)}); el resto está en el Excel`
    : `${fmt(D.cves.length)} CVE`;
  pintarTabla();

  // ---------- Metodología, descargas y pie
  for (const n of D.niveles) {
    $("#lista-niveles").append(el("li", {}, chipNivel(n.nivel), ` corregir en ${n.plazo} — ${fmt(n.cve)} CVE`));
  }
  const desc = $("#descargas");
  const base = location.href.replace(/[#?].*$/, "").replace(/index\.html$/, "");
  if (D.descargas && D.descargas.excel) {
    desc.append(el("a", { href: D.descargas.excel, download: "" }, el("span", { text: "Reporte Excel (8+ hojas con gráficos)" }), el("span", { class: "sub", text: ".xlsx" })));
  }
  for (const c of (D.descargas && D.descargas.csv) || []) {
    desc.append(el("a", { href: c, download: "" }, el("span", { text: c.replace("powerbi/", "") }), el("span", { class: "sub", text: "CSV · Power BI" })));
  }
  $("#url-pbi").textContent = base.startsWith("http") ? base + "powerbi/consolidado.csv" : "(publica el panel en GitHub Pages para obtener la URL)";
  $("#pie").append(
    `Vigía v${m.version} · Datos: `,
    el("a", { href: "https://nvd.nist.gov", target: "_blank", rel: "noopener noreferrer", text: "NIST NVD" }), ", ",
    el("a", { href: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog", target: "_blank", rel: "noopener noreferrer", text: "CISA KEV" }), ", ",
    el("a", { href: "https://github.com/advisories", target: "_blank", rel: "noopener noreferrer", text: "GitHub Advisory Database" }), " y ",
    el("a", { href: "https://www.first.org/epss", target: "_blank", rel: "noopener noreferrer", text: "FIRST EPSS" }),
    ". Este panel es informativo: confirma versiones afectadas en el aviso de cada fabricante.");
})();
