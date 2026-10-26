"use strict";
(function () {
  const D = JSON.parse(document.getElementById("datos").textContent);
  const $ = (s) => document.querySelector(s);
  const SVG = "http://www.w3.org/2000/svg";

  // ---------- utilidades: todo el texto se pinta con textContent (nunca innerHTML con datos)
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
  function svgEl(tag, attrs) {
    const e = document.createElementNS(SVG, tag);
    for (const [k, v] of Object.entries(attrs || {})) e.setAttribute(k, v);
    return e;
  }
  const fmt = (n, d = 0) =>
    n == null ? "—" : Number(n).toLocaleString("es-DO", { minimumFractionDigits: d, maximumFractionDigits: d });
  const plural = (n, uno, varios) => (n === 1 ? uno : varios);
  function urlSegura(u) {
    try {
      const x = new URL(u);
      return x.protocol === "https:" || x.protocol === "http:" ? x.href : null;
    } catch (_) { return null; }
  }
  function fecha(iso, opciones) {
    const [y, m, d] = iso.split("-").map(Number);
    return new Date(y, (m || 1) - 1, d || 1).toLocaleDateString("es-DO", opciones);
  }
  // "ProFTPD, ProFTPD" -> "ProFTPD"; "Cisco, Catalyst SD-WAN" se queda igual
  function productoDe(c, extra) {
    const prov = c.prov || "", prod = c.prod || "";
    const partes = prod && prov && prod.toLowerCase().startsWith(prov.toLowerCase()) ? [prod] : [prov, prod];
    return partes.concat(extra || []).filter(Boolean).join(", ");
  }
  const capital = (t) => (t ? t.charAt(0).toUpperCase() + t.slice(1).toLowerCase() : t);

  const SEV = {
    "CRÍTICA": "--sev-critica", "ALTA": "--sev-alta", "MEDIA": "--sev-media",
    "BAJA": "--sev-baja", "NINGUNA": "--sev-sin", "SIN CALIFICAR": "--sev-sin",
  };
  const NIVEL = {
    INMEDIATA: { c: "--niv-inmediata", titulo: "Corregir en 24 a 48 horas" },
    URGENTE: { c: "--niv-urgente", titulo: "Corregir esta semana" },
    PLANIFICADA: { c: "--niv-planificada", titulo: "Corregir este mes" },
    RUTINA: { c: "--niv-rutina", titulo: "En el próximo ciclo de parches" },
  };
  const nombreNivel = { INMEDIATA: "Inmediata", URGENTE: "Urgente", PLANIFICADA: "Planificada", RUTINA: "Rutina" };

  function sevEtiqueta(s) {
    if (!s) return null;
    const e = el("span", { class: "sev", text: capital(s) });
    e.style.setProperty("--c", `var(${SEV[s] || "--sev-sin"})`);
    return e;
  }
  function nivelEtiqueta(n) {
    const e = el("span", { class: "nivel", text: nombreNivel[n] || n || "—" });
    e.style.setProperty("--c", `var(${(NIVEL[n] || {}).c || "--niv-rutina"})`);
    return e;
  }
  function enlaceCve(c) {
    const u = urlSegura(c.url);
    return u ? el("a", { class: "cve", href: u, target: "_blank", rel: "noopener noreferrer", text: c.id })
             : el("span", { class: "cve", text: c.id });
  }

  // ---------- tema
  const raiz = document.documentElement;
  try { const t = localStorage.getItem("tema"); if (t) raiz.dataset.theme = t; } catch (_) {}
  const temaActual = () => raiz.dataset.theme || (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
  const rotularTema = () => { $("#tema").textContent = temaActual() === "dark" ? "Modo claro" : "Modo oscuro"; };
  $("#tema").addEventListener("click", () => {
    raiz.dataset.theme = temaActual() === "dark" ? "light" : "dark";
    try { localStorage.setItem("tema", raiz.dataset.theme); } catch (_) {}
    rotularTema();
  });
  matchMedia("(prefers-color-scheme: dark)").addEventListener("change", rotularTema);
  rotularTema();

  // ---------- parte de guardia
  const m = D.meta, K = D.kpis;
  const generado = new Date(m.generado);
  const horas = (Date.now() - generado.getTime()) / 36e5;
  $("#actualizado").textContent = "Revisado " + generado.toLocaleString("es-DO", { dateStyle: "medium", timeStyle: "short" });
  if (horas > 36) {
    $("#faro").classList.add("viejo");
    $("#actualizado").textContent += ", hace más de un día";
  }
  $("#periodo").textContent =
    `Parte de vigilancia del ${fecha(m.desde, { day: "numeric", month: "long" })} al ${fecha(m.hasta, { day: "numeric", month: "long", year: "numeric" })}`;

  const h1 = $("#titular");
  if (K.inmediata > 0) {
    h1.append(el("span", { class: "cifra", text: fmt(K.inmediata) }),
      ` ${plural(K.inmediata, "vulnerabilidad pide", "vulnerabilidades piden")} corrección inmediata.`);
    $("#bajada").textContent =
      `Están siendo explotadas o tienen alta probabilidad de serlo. ` +
      (K.urgente ? `Después vienen ${fmt(K.urgente)} para corregir esta semana.` : "");
  } else {
    h1.classList.add("calma");
    h1.append("Nada urgente hoy. ", el("span", { class: "cifra", text: fmt(K.urgente) }),
      ` ${plural(K.urgente, "para", "para")} esta semana.`);
    $("#bajada").textContent = "Ninguna vulnerabilidad del periodo llega al nivel de corrección inmediata.";
  }

  const resumen = [
    [K.total, `${plural(K.total, "CVE publicada", "CVE publicadas")} en ${m.fuentes.length} ${plural(m.fuentes.length, "fuente", "fuentes")}`],
    [K.explotadas, `${plural(K.explotadas, "explotada", "explotadas")} activamente según CISA`, "naranja"],
    [K.criticas, `de severidad crítica`],
  ];
  if (D.inventario) resumen.push([D.inventario.total_cve, `afectan el software de la organización`]);
  for (const [n, txt, clase] of resumen) {
    $("#resumen").append(el("div", { class: clase }, el("dt", { text: fmt(n) }), el("dd", { text: txt })));
  }

  // ---------- horizonte
  const S = D.serie;
  const etiquetas = S.etiquetas;
  const kev = S.series["CISA KEV"] || etiquetas.map(() => 0);
  const totales = etiquetas.map((_, i) =>
    Object.entries(S.series).filter(([f]) => f !== "CISA KEV").reduce((a, [, v]) => a + (v[i] || 0), 0));
  const maximo = Math.max(1, ...totales);
  const maxKev = Math.max(1, ...kev);
  const n = etiquetas.length, alto = 150, techo = 34;
  const svg = $("#svg-horizonte");
  const tip = $("#tip");
  const diaria = S.granularidad === "día";
  const nombreDia = (e) => diaria ? fecha(e, { weekday: "short", day: "numeric", month: "short" }) : fecha(e + "-01", { month: "long", year: "numeric" });
  function dibujarHorizonte() {
    const ancho = Math.max(240, svg.clientWidth || svg.parentNode.clientWidth);
    const paso = ancho / n;
    const hueco = Math.min(6, Math.max(1, paso * 0.28));
    svg.setAttribute("viewBox", `0 0 ${ancho} ${alto}`);
    svg.replaceChildren();
    etiquetas.forEach((e, i) => {
      const g = svgEl("g", { class: "zona", tabindex: "0" });
      g.style.setProperty("--i", i);
      const h = Math.max(totales[i] ? 2 : 0, (totales[i] / maximo) * (alto - techo - 6));
      g.append(svgEl("rect", { x: i * paso, y: 0, width: paso, height: alto, fill: "transparent" }));
      g.append(svgEl("rect", { class: "barra-dia", x: i * paso + hueco / 2, y: alto - h, width: Math.max(1, paso - hueco), height: h, rx: Math.min(3, paso / 6) }));
      if (kev[i] > 0) {
        const r = Math.min(paso / 2.2, 3.5 + 3 * Math.sqrt(kev[i] / maxKev));
        g.append(svgEl("circle", { class: "punto", cx: i * paso + paso / 2, cy: alto - h - r - 5, r }));
      }
      const t = svgEl("title", {});
      t.textContent = `${nombreDia(e)}: ${fmt(totales[i])} CVE` + (kev[i] ? `, ${fmt(kev[i])} ${plural(kev[i], "agregada", "agregadas")} a KEV` : "");
      g.append(t);
      const mostrar = (x, y) => {
        // replaceChildren escribe "null" si recibe null: se filtran los vacíos
        tip.replaceChildren(...[el("b", { text: nombreDia(e) }), el("br"), `${fmt(totales[i])} CVE publicadas`,
          kev[i] ? el("span", {}, el("br"), `${fmt(kev[i])} ${plural(kev[i], "confirmada", "confirmadas")} por CISA`) : null]
          .filter(Boolean));
        tip.style.display = "block";
        const w = tip.offsetWidth;
        tip.style.left = Math.min(window.innerWidth - w - 8, Math.max(8, x - w / 2)) + "px";
        tip.style.top = (y - tip.offsetHeight - 14) + "px";
      };
      g.addEventListener("mousemove", (ev) => mostrar(ev.clientX, ev.clientY));
      g.addEventListener("focus", () => { const r = g.getBoundingClientRect(); mostrar(r.left + r.width / 2, r.top + 40); });
      g.addEventListener("mouseleave", () => { tip.style.display = "none"; });
      g.addEventListener("blur", () => { tip.style.display = "none"; });
      svg.append(g);
    });
    svg.append(svgEl("line", { class: "base", x1: 0, x2: ancho, y1: alto - 0.5, y2: alto - 0.5 }));
  }
  dibujarHorizonte();
  // En celulares un toque deja el aviso "pegado": se oculta al desplazarse o tocar fuera
  const ocultarTip = () => { tip.style.display = "none"; };
  window.addEventListener("scroll", ocultarTip, { passive: true });
  document.addEventListener("touchstart", (ev) => { if (!svg.contains(ev.target)) ocultarTip(); }, { passive: true });
  let ultimoAncho = svg.clientWidth;
  if ("ResizeObserver" in window) {
    new ResizeObserver(() => {
      if (Math.abs(svg.clientWidth - ultimoAncho) > 4) { ultimoAncho = svg.clientWidth; $("#horizonte").classList.remove("anim"); dibujarHorizonte(); }
    }).observe(svg);
  }
  const pico = totales.indexOf(maximo);
  $("#h-horizonte").textContent =
    `CVE publicadas por ${S.granularidad}. El pico fue ${nombreDia(etiquetas[pico])} con ${fmt(maximo)}. ` +
    `${fmt(kev.filter(Boolean).length)} ${plural(kev.filter(Boolean).length, "día", "días")} con vulnerabilidades agregadas a KEV.`;
  const eje = $("#eje");
  const marcas = n > 1 ? [0, Math.floor((n - 1) / 2), n - 1] : [0];
  for (const i of marcas) eje.append(el("span", { text: diaria ? fecha(etiquetas[i], { day: "numeric", month: "short" }) : nombreDia(etiquetas[i]) }));
  if (!matchMedia("(prefers-reduced-motion: reduce)").matches) $("#horizonte").classList.add("anim");

  // ---------- cola de corrección (agrupada por plazo)
  const POR_GRUPO = 5;
  const cola = $("#cola");
  const conteoNivel = Object.fromEntries(D.niveles.map((x) => [x.nivel, x.cve]));
  for (const nivel of ["INMEDIATA", "URGENTE", "PLANIFICADA"]) {
    const lista = D.cves.filter((c) => c.nivel === nivel);
    const total = conteoNivel[nivel] || 0;
    if (!total && nivel !== "INMEDIATA") continue;
    const grupo = el("article", { class: "grupo " + nivel.toLowerCase(), "aria-label": NIVEL[nivel].titulo });
    const punto = el("span", { class: "marca-nivel" });
    punto.style.background = `var(${NIVEL[nivel].c})`;
    grupo.append(el("h3", {}, punto, NIVEL[nivel].titulo, el("span", { class: "cuantas", text: fmt(total) })));
    if (!lista.length) grupo.append(el("p", { class: "vacio", text: "Ninguna en este periodo." }));
    for (const c of lista.slice(0, POR_GRUPO)) {
      const producto = productoDe(c);
      grupo.append(el("div", { class: "fila" },
        el("div", { class: "puntaje", title: c.motivo || "" }, fmt(c.puntaje), el("small", { text: "de 100" })),
        el("div", { class: "que" },
          el("div", { class: "linea1" }, enlaceCve(c), sevEtiqueta(c.sev),
            c.kev ? el("span", { class: "explotada", text: c.rans ? "Explotada, usada en ransomware" : "Explotada" }) : null,
            c.activos ? el("span", { class: "afecta", text: "Afecta: " + c.activos }) : null),
          el("div", { class: "titulo", text: c.titulo || "" }),
          producto ? el("div", { class: "producto", text: producto }) : null),
        el("div", { class: "datos-fila" },
          el("div", {}, el("b", { text: fmt(c.cvss, 1) }), "CVSS"),
          el("div", {}, el("b", { text: c.epss == null ? "—" : fmt(c.epss * 100, c.epss < 0.1 ? 1 : 0) + "%" }), "EPSS"),
          el("div", {}, el("b", { text: c.limite ? fecha(c.limite, { day: "numeric", month: "short" }) : "—" }), "Límite"))));
    }
    if (total > POR_GRUPO) {
      const ver = el("a", { class: "mas", href: "#explorar", text: `Ver las ${fmt(total)}` });
      ver.addEventListener("click", () => { $("#f-nivel").value = nivel; pagina = 0; pintarTabla(); });
      grupo.append(ver);
    }
    cola.append(grupo);
  }

  // ---------- inventario
  if (D.inventario) {
    const inv = D.inventario;
    $("#sec-inv").hidden = false;
    $("#inv-bajada").textContent =
      `Vigía cruza cada vulnerabilidad con el inventario de software de la organización (${inv.nombre}, ${inv.activos.length} activos).`;
    const nota = $("#inv-nota");
    nota.append(
      el("p", { class: "grande", text: `${inv.total_afectados} de ${inv.activos.length}` }),
      el("p", { text: `activos tienen al menos una vulnerabilidad publicada en el periodo.` }),
      el("p", { text: "La coincidencia es por proveedor y producto. Antes de parchar, confirma la versión instalada en el aviso del fabricante." }));
    const maxActivo = Math.max(1, ...inv.activos.map((a) => a.cve));
    for (const a of inv.activos) {
      const barra = el("span");
      barra.style.width = a.cve ? Math.max(3, (Math.log10(a.cve + 1) / Math.log10(maxActivo + 1)) * 100) + "%" : "0";
      $("#activos").append(el("li", {},
        el("div", {}, el("span", { class: "nombre", text: a.activo }), el("span", { class: "soft", text: `${a.producto}, criticidad ${a.criticidad.toLowerCase()}` })),
        a.cve ? el("div", { class: "exposicion" + (a.explotadas ? " critica" : ""), title: "Escala logarítmica" }, barra) : el("div"),
        a.cve
          ? el("div", { class: "conteo" }, el("b", { text: fmt(a.cve) }), ` ${plural(a.cve, "CVE", "CVE")}`,
              a.explotadas ? el("span", { class: "explotada", text: fmt(a.explotadas) + plural(a.explotadas, " explotada", " explotadas") }) : null)
          : el("div", { class: "conteo limpio", text: "Sin hallazgos" })));
    }
  } else {
    $("#lbl-inv").hidden = true;
  }

  // ---------- panorama
  const ordenSev = ["CRÍTICA", "ALTA", "MEDIA", "BAJA", "SIN CALIFICAR"];
  const totalSev = ordenSev.reduce((a, s) => a + (D.severidad[s] || 0), 0) || 1;
  const apilada = $("#apilada");
  apilada.setAttribute("aria-label", ordenSev.map((s) => `${capital(s)}: ${fmt(D.severidad[s] || 0)}`).join(", "));
  for (const s of ordenSev) {
    const v = D.severidad[s] || 0;
    if (!v) continue;
    const seg = el("span", { title: `${capital(s)}: ${fmt(v)}` });
    seg.style.flex = String(v);
    seg.style.background = `var(${SEV[s]})`;
    apilada.append(seg);
    const i = el("i"); i.style.background = `var(${SEV[s]})`;
    $("#leyenda-sev").append(el("div", {}, i, el("b", { text: fmt(v) }), el("span", { text: `${capital(s)}, ${fmt((v / totalSev) * 100)}%` })));
  }
  function ranking(destino, filas) {
    const max = Math.max(1, ...filas.map((f) => f.n));
    for (const f of filas) {
      const r = el("span"); r.style.width = (f.n / max) * 100 + "%";
      destino.append(el("li", {},
        el("span", { class: "etq", title: f.titulo || f.etq }, f.etq, f.extra ? el("small", { text: f.extra }) : null),
        el("span", { class: "n", text: fmt(f.n) }),
        el("span", { class: "riel" }, r)));
    }
  }
  ranking($("#proveedores"), D.proveedores.slice(0, 8).map((p) => ({ etq: p.nombre, n: p.cve, extra: p.criticas ? `${fmt(p.criticas)} críticas` : "" })));
  ranking($("#cwe"), D.cwe.slice(0, 8).map((c) => ({ etq: c.nombre || c.cwe, n: c.cve, extra: c.cwe, titulo: `${c.cwe} ${c.nombre || ""}` })));

  // ---------- explorador
  const POR_PAGINA = 25;
  let pagina = 0;
  for (const nv of D.niveles) $("#f-nivel").append(el("option", { value: nv.nivel, text: NIVEL[nv.nivel] ? NIVEL[nv.nivel].titulo : nv.nivel }));
  for (const s of Object.keys(D.severidad)) if (D.severidad[s]) $("#f-sev").append(el("option", { value: s, text: capital(s) }));
  const indice = D.cves.map((c) => [c.id, c.titulo, c.prov, c.prod, c.eco, c.activos, c.cwe].filter(Boolean).join(" ").toLowerCase());
  $("#exp-bajada").textContent = D.total_cves > D.cves.length
    ? `Aquí están las ${fmt(D.cves.length)} de mayor prioridad. Las ${fmt(D.total_cves)} completas están en el Excel.`
    : `Las ${fmt(D.cves.length)} vulnerabilidades del periodo.`;

  const tabla = $("#tabla-cve");
  tabla.append(el("thead", {}, el("tr", {},
    el("th", { class: "r", text: "Índice" }), el("th", { text: "Plazo" }), el("th", { text: "CVE" }),
    el("th", { text: "Qué es" }), el("th", { text: "Severidad" }), el("th", { class: "r", text: "CVSS" }),
    el("th", { class: "r", text: "EPSS" }), el("th", { text: "Publicada" }))));
  const cuerpo = el("tbody");
  tabla.append(cuerpo);

  function filtrados() {
    const q = $("#f-texto").value.trim().toLowerCase();
    const niv = $("#f-nivel").value, sev = $("#f-sev").value;
    const soloKev = $("#f-kev").checked, soloInv = $("#f-inv").checked;
    return D.cves.filter((c, i) => (!q || indice[i].includes(q)) && (!niv || c.nivel === niv) &&
      (!sev || c.sev === sev) && (!soloKev || c.kev) && (!soloInv || c.activos));
  }
  function pintarTabla() {
    const lista = filtrados();
    const paginas = Math.max(1, Math.ceil(lista.length / POR_PAGINA));
    pagina = Math.min(Math.max(0, pagina), paginas - 1);
    const visibles = lista.slice(pagina * POR_PAGINA, (pagina + 1) * POR_PAGINA);
    cuerpo.replaceChildren(...visibles.map((c) => el("tr", {},
      el("td", { class: "r", text: fmt(c.puntaje) }),
      el("td", {}, nivelEtiqueta(c.nivel)),
      el("td", {}, enlaceCve(c), c.kev ? el("span", { class: "sub" }, el("span", { class: "explotada", text: "Explotada" })) : null),
      el("td", {}, el("span", { text: c.titulo || "" }),
        el("span", { class: "sub", text: productoDe(c, [c.eco]) }),
        c.activos ? el("span", { class: "sub afecta", text: "Afecta: " + c.activos }) : null),
      el("td", {}, sevEtiqueta(c.sev)),
      el("td", { class: "r", text: fmt(c.cvss, 1) }),
      el("td", { class: "r", text: c.epss == null ? "—" : fmt(c.epss * 100, 1) + "%" }),
      el("td", { class: "num", text: c.fecha ? fecha(c.fecha, { day: "numeric", month: "short" }) : "—" }))));
    if (!visibles.length) cuerpo.append(el("tr", {}, el("td", { colspan: 8, text: "Ninguna vulnerabilidad coincide. Prueba con menos filtros." })));
    $("#pag-info").textContent = lista.length
      ? `${fmt(pagina * POR_PAGINA + 1)} a ${fmt(pagina * POR_PAGINA + visibles.length)} de ${fmt(lista.length)}`
      : "0 resultados";
    $("#pag-ant").disabled = pagina === 0;
    $("#pag-sig").disabled = pagina >= paginas - 1;
  }
  for (const id of ["#f-texto", "#f-nivel", "#f-sev", "#f-kev", "#f-inv"]) {
    $(id).addEventListener("input", () => { pagina = 0; pintarTabla(); });
  }
  $("#pag-ant").addEventListener("click", () => { pagina--; pintarTabla(); });
  $("#pag-sig").addEventListener("click", () => { pagina++; pintarTabla(); });
  pintarTabla();

  // ---------- método
  for (const nv of D.niveles) {
    const p = el("span", { class: "nivel" });
    p.style.setProperty("--c", `var(${(NIVEL[nv.nivel] || {}).c})`);
    p.textContent = nombreNivel[nv.nivel];
    const rangos = { INMEDIATA: "80 a 100 puntos, de 24 a 48 horas", URGENTE: "60 a 79 puntos, 7 días", PLANIFICADA: "40 a 59 puntos, 30 días", RUTINA: "0 a 39 puntos, próximo ciclo" };
    $("#plazos").append(el("li", {}, el("div", {}, p, el("span", { class: "rango", text: rangos[nv.nivel] || "" })),
      el("span", { class: "cuantas", text: fmt(nv.cve) })));
  }

  // ---------- datos
  const desc = $("#descargas");
  if (D.descargas && D.descargas.excel) {
    desc.append(el("a", { class: "descarga", href: D.descargas.excel, download: "" },
      el("b", { text: "Reporte en Excel" }), el("span", { text: "Resumen con gráficos, prioridad, inventario y todos los registros" })));
  }
  const nombresCsv = {
    "consolidado.csv": "Una fila por vulnerabilidad, con su prioridad",
    "registros.csv": "Lo que reporta cada fuente por separado",
    "inventario_afectaciones.csv": "Qué vulnerabilidad afecta a qué activo",
    "cwe_por_cve.csv": "Tipos de debilidad de cada vulnerabilidad",
    "por_mes.csv": "Conteo mensual por fuente",
  };
  for (const c of (D.descargas && D.descargas.csv) || []) {
    const nombre = c.replace("powerbi/", "");
    desc.append(el("a", { class: "descarga", href: c, download: "" }, el("b", { text: nombre }), el("span", { text: nombresCsv[nombre] || "CSV para Power BI" })));
  }
  const base = location.href.replace(/[#?].*$/, "").replace(/index\.html$/, "");
  const urlPbi = base.startsWith("http") ? base + "powerbi/consolidado.csv" : "Publica el panel en GitHub Pages para obtener la dirección";
  $("#url-pbi").textContent = urlPbi;
  $("#copiar").addEventListener("click", async () => {
    try { await navigator.clipboard.writeText(urlPbi); $("#copiar").textContent = "Copiada"; }
    catch (_) { $("#copiar").textContent = "Cópiala a mano"; }
    setTimeout(() => { $("#copiar").textContent = "Copiar"; }, 2000);
  });

  $("#pie").append(`Vigía ${m.version}. Datos de `,
    el("a", { href: "https://nvd.nist.gov", target: "_blank", rel: "noopener noreferrer", text: "NVD" }), ", ",
    el("a", { href: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog", target: "_blank", rel: "noopener noreferrer", text: "CISA KEV" }), ", ",
    el("a", { href: "https://github.com/advisories", target: "_blank", rel: "noopener noreferrer", text: "GitHub Advisory" }), " y ",
    el("a", { href: "https://www.first.org/epss", target: "_blank", rel: "noopener noreferrer", text: "FIRST EPSS" }), ".");
})();
