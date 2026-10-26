# CVE Explorer

[![Abrir en GitHub Codespaces](https://github.com/codespaces/badge.svg)](https://codespaces.new/TU_USUARIO/cve-explorer)

![Python](https://img.shields.io/badge/python-3.10%2B-blue) ![Pruebas](https://github.com/TU_USUARIO/cve-explorer/actions/workflows/pruebas.yml/badge.svg) ![Licencia](https://img.shields.io/badge/licencia-MIT-green)

**Panel en vivo:** https://TU_USUARIO.github.io/cve-explorer/ (se actualiza solo todos los días)

Programa en Python que **consulta vulnerabilidades CVE en varias bases de datos**,
permite elegir el **rango de fechas (dentro de los últimos 5 años)** y las **fuentes**,
y **exporta** los resultados a **Excel** (con tablas y gráficos) y a **CSV para Power BI**.

Además de extraer los datos, responde las dos preguntas que se hace un equipo de seguridad real:

1. **¿Qué parcho primero?** → índice de prioridad 0-100 (CVSS + EPSS + CISA KEV + ransomware).
2. **¿Qué me afecta a mí?** → cruce con el inventario de software de una empresa (ficticia).

Y lo publica solo: **panel web en GitHub Pages** actualizado cada mañana y **alertas a Discord**
cuando CISA confirma una vulnerabilidad nueva explotada.

---

## Qué hace diferente

| Lo normal | CVE Explorer |
|---|---|
| Baja CVE de una fuente | Consolida **3 fuentes** (NVD, CISA KEV, GitHub) + **EPSS**, una fila por CVE |
| Ordena por CVSS | **Índice de prioridad** explicable: dice *por qué* y *en cuánto tiempo* corregir |
| Lista todo | Cruza con un **inventario** y muestra solo lo que afecta a la organización |
| Un Excel que hay que volver a generar | **Panel web** que GitHub Actions actualiza solo y Power BI puede leer por URL |
| Hay que revisarlo | **Alerta a Discord** cuando CISA agrega una CVE explotada |
| Seguridad no considerada | Anti-XSS, CSP con hash, SRI, anti-inyección de fórmulas en Excel, webhook validado |

---

## Bases de datos

| Clave | Fuente | Qué aporta | Filtro de fecha | Llave |
|---|---|---|---|---|
| `nvd` | [NVD – NIST](https://nvd.nist.gov) | Catálogo oficial: CVSS v2/v3/v4, CWE, productos (CPE) | Publicación | Opcional `NVD_API_KEY` |
| `kev` | [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | CVE **explotadas activamente**, ransomware, fecha límite | Fecha en que CISA la agregó | No |
| `ghsa` | [GitHub Advisory Database](https://github.com/advisories) | Vulnerabilidades en librerías (npm, pip, Maven…) | Publicación | Opcional `GITHUB_TOKEN` |
| — | [FIRST EPSS](https://www.first.org/epss) | Probabilidad de explotación en los próximos 30 días | — | No |

Las CVE de CISA KEV suelen ser antiguas (se publicaron hace meses o años y CISA las agrega cuando
detecta ataques), así que el programa **completa su CVSS consultando la NVD por ID**.

---

## Índice de prioridad de parcheo

```
  4 × CVSS                      gravedad          (máx. 40)
+ 25 × percentil EPSS           probabilidad      (máx. 25)
+ 25 si está en CISA KEV        ya la explotan
+ 10 si se usa en ransomware     impacto conocido
───────────────────────────────────────────────
  0 a 100   ·   pisos: KEV ≥ 60 · ransomware ≥ 80 · CVSS ≥ 9 → ≥ 40
```

| Nivel | Puntaje | Corregir en |
|---|---|---|
| INMEDIATA | 80 – 100 | 24–48 horas |
| URGENTE | 60 – 79 | 7 días |
| PLANIFICADA | 40 – 59 | 30 días |
| RUTINA | 0 – 39 | Próximo ciclo de parches |

**Por qué no solo CVSS:** el CVSS mide qué tan grave *sería* un ataque, no qué tan probable es.
Miles de CVE tienen CVSS alto y nunca se explotan; CISA (BOD 22-01) pide corregir primero
lo que ya se está explotando. Por eso el índice suma gravedad, probabilidad (EPSS) y explotación
real (KEV). Cada CVE trae una columna **Motivo** que explica su puntaje.
La fórmula está en `cve_explorer/prioridad.py` y sus pesos se pueden ajustar.

## Inventario: ¿qué me afecta?

`inventario/empresa_ejemplo.csv` describe el software de una empresa ficticia (firewall, VPN,
servidores, etc.). El programa cruza cada CVE con ese inventario por **proveedor + producto**:

```csv
activo,proveedor,producto,version,criticidad
Firewall perimetral,Fortinet,FortiOS,7.2.5,Alta
Controlador de dominio,Microsoft,Windows Server,2019,Alta
```

Usa tu propio archivo con `--inventario mi_empresa.csv` (o `--sin-inventario`).
La versión no se compara automáticamente: el resultado es un primer filtro y la versión
exacta se confirma en el aviso del fabricante.

---

## Inicio rápido en GitHub Codespaces

1. Clic en el botón **Abrir en GitHub Codespaces** de arriba (o **Code → Codespaces → Create codespace on main**).
2. Esperar a que instale las dependencias (lo hace solo, ver `.devcontainer/`).
3. En la terminal:

```bash
python main.py                                   # menú interactivo
python main.py --ultimos-dias 30 --fuentes todas # directo
python -m http.server 8000 -d output/dashboard   # ver el panel (se abre en el navegador)
```

> En Codespaces la variable `GITHUB_TOKEN` ya existe, así que GitHub Advisory funciona a velocidad completa.
> Para la NVD, agrega `NVD_API_KEY` en **Settings → Codespaces → Secrets** (gratis en
> <https://nvd.nist.gov/developers/request-an-api-key>).

## Instalación local

```bash
git clone https://github.com/TU_USUARIO/cve-explorer.git
cd cve-explorer
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env               # opcional: poner las llaves
```

---

## Uso

### Menú interactivo

```bash
python main.py
```

```
[1] Rango de fechas (permitido: 2021-10-25 a 2026-10-25)
    1) Últimos 7 días   2) Últimos 30 días   3) Últimos 90 días
    4) Último año       5) Últimos 5 años    6) Personalizado
[2] Bases de datos a consultar
    1) NVD   2) CISA KEV   3) GitHub Advisory
[3] Exportar como  1) Excel + CSV   2) Solo Excel   3) Solo CSV
[4] ¿Agregar probabilidad de explotación EPSS? (S/n)
```

### Con parámetros

```bash
# Últimos 30 días en todas las fuentes
python main.py --ultimos-dias 30 --fuentes todas

# Rango exacto, solo NVD y CISA KEV
python main.py --desde 2025-01-01 --hasta 2025-06-30 --fuentes nvd,kev

# Todo lo que CISA marcó como explotado en 2024
python main.py --desde 2024-01-01 --hasta 2024-12-31 --fuentes kev

# Con tu propio inventario
python main.py --ultimos-dias 90 --fuentes todas --inventario mi_empresa.csv

# Probar las alertas de Discord con lo agregado a KEV en la última semana
python main.py --ultimos-dias 7 --fuentes kev --alerta-discord --dias-alerta 7
```

| Opción | Descripción |
|---|---|
| `--desde`, `--hasta` | Rango `AAAA-MM-DD` (máximo 5 años hacia atrás; `--hasta` por defecto es hoy) |
| `--ultimos-dias N` | Atajo para los últimos N días |
| `--fuentes` | `nvd`, `kev`, `ghsa` separados por coma, o `todas` |
| `--formato` | `excel`, `csv` o `ambos` (por defecto) |
| `--salida` | Carpeta de salida (por defecto `output/`) |
| `--inventario CSV` / `--sin-inventario` | Inventario a cruzar (por defecto el de ejemplo) |
| `--dashboard CARPETA` / `--sin-dashboard` | Dónde generar el panel web (por defecto `output/dashboard/`) |
| `--alerta-discord`, `--dias-alerta N` | Enviar alerta de CVE nuevas en KEV (usa `DISCORD_WEBHOOK_URL`) |
| `--sin-epss` | No consultar EPSS |
| `--sin-completar` | No completar en la NVD el CVSS de las CVE de KEV |
| `--limite N` | Máximo de registros por fuente (para pruebas) |
| `--idioma es\|en` | Idioma preferido de las descripciones de la NVD |
| `--incluir-sin-cve` | Incluye avisos de GitHub sin CVE asignado |
| `--listar-fuentes` | Muestra las bases disponibles |

---

## Automatización en GitHub

| Workflow | Cuándo | Qué hace |
|---|---|---|
| `pruebas.yml` | Cada `push` | Corre las 41 pruebas automáticas |
| `panel-diario.yml` | Todos los días 7:17 a. m. (RD) y a mano | Consulta 30 días, publica el panel en **GitHub Pages**, avisa a Discord |
| `generar-reporte.yml` | A mano (Actions → Run workflow) | Reporte con fechas/fuentes a elección; el Excel queda en *Artifacts* |

**Activar el panel (una sola vez):**

1. **Settings → Pages → Source: GitHub Actions**.
2. **Settings → Secrets and variables → Actions → New repository secret**:
   - `NVD_API_KEY` (recomendado)
   - `DISCORD_WEBHOOK_URL` (opcional; en Discord: *Editar canal → Integraciones → Webhooks*)
3. **Actions → Panel diario → Run workflow**.

El panel publica también el Excel y los CSV, así que **Power BI puede conectarse por URL**
(*Obtener datos → Web →* `https://TU_USUARIO.github.io/cve-explorer/powerbi/consolidado.csv`)
y con **Actualizar** trae los datos del día. Ver [docs/GUIA_POWER_BI.md](docs/GUIA_POWER_BI.md).

---

## Qué se genera

```
output/
├── cve_20250101_20250630_….xlsx     reporte Excel (uno por corrida)
├── powerbi/                          CSV para Power BI (se sobrescriben)
│   ├── consolidado.csv               una fila por CVE (con prioridad)
│   ├── registros.csv                 una fila por CVE y fuente
│   ├── inventario_afectaciones.csv   activo × CVE que lo afecta
│   ├── cwe_por_cve.csv               una fila por CVE y CWE
│   └── por_mes.csv                   conteo mensual por fuente
└── dashboard/
    └── index.html                    panel web (+ copia del Excel y CSV para descargar)
```

### Hojas del Excel

| Hoja | Contenido |
|---|---|
| **Resumen** | 8 indicadores y 4 gráficos |
| **Prioridad** | Top 100 por índice de prioridad, con nivel, plazo y motivo |
| **Activos** | Cada activo del inventario con cuántas CVE lo afectan |
| **Inventario** | Detalle activo × CVE |
| **Consolidado** | Una fila por CVE, tabla filtrable con colores |
| **Registros** | Datos tal cual los reporta cada fuente |
| **Por_Mes / Por_Severidad / Top_Proveedores / Top_CWE** | Resúmenes |
| **Parametros** | Rango, fuentes, fórmula, resultado de cada consulta y advertencias |

---

## Estructura del proyecto

```
cve-explorer/
├── main.py                       punto de entrada
├── cve_explorer/
│   ├── cli.py                    menú interactivo, parámetros y flujo principal
│   ├── config.py                 llaves y ajustes (lee .env)
│   ├── fechas.py                 validación de 5 años y división en tramos
│   ├── modelo.py                 registro común y normalización de severidad
│   ├── cliente_http.py           GET con reintentos y control de límites
│   ├── fuentes/                  una clase por base de datos (heredan de FuenteBase)
│   │   ├── nvd.py · cisa_kev.py · github_advisory.py
│   ├── epss.py                   probabilidad de explotación (FIRST)
│   ├── procesamiento.py          consolidación y tablas resumen (pandas)
│   ├── prioridad.py              índice de prioridad de parcheo
│   ├── inventario.py             cruce con el software de la empresa
│   ├── exportar.py               Excel con formato/gráficos y CSV
│   ├── dashboard.py              panel web
│   ├── plantillas/               HTML y JavaScript del panel
│   └── alertas.py                alertas a Discord
├── inventario/empresa_ejemplo.csv
├── tests/                        41 pruebas con datos de ejemplo (sin internet)
├── docs/GUIA_POWER_BI.md
├── .devcontainer/                configuración de Codespaces
└── .github/workflows/            pruebas, panel diario y reporte bajo demanda
```

### Flujo

```
                    ┌─ NVD (tramos de 120 días × páginas de 2000)
fechas + fuentes ──►├─ CISA KEV (catálogo completo, filtro por fecha)
                    └─ GitHub Advisory (páginas de 100 por cursor)
                              │
                 consolidar (1 fila por CVE) ──► completar CVSS de KEV en la NVD
                              │
                       EPSS ──► índice de prioridad ──► cruce con inventario
                              │
              ┌───────────────┼────────────────┬──────────────┐
            Excel        CSV Power BI     Panel web       Discord
```

### Agregar otra base de datos

1. Crear `cve_explorer/fuentes/mi_fuente.py` con una clase que herede de `FuenteBase` e implemente `consultar(desde, hasta)` devolviendo una lista de `Registro`.
2. Registrarla en `cve_explorer/fuentes/__init__.py` dentro de `FUENTES`.

---

## Seguridad del propio programa

| Riesgo | Control aplicado |
|---|---|
| Fuga de llaves | Llaves por variables de entorno / `.env` (en `.gitignore`) y *GitHub Secrets* |
| Bloqueo por abuso de API | Pausas, `Retry-After`, `X-RateLimit-*`, reintentos exponenciales |
| **Inyección de fórmulas** en Excel/CSV (OWASP) | Textos que empiezan con `= + - @` se neutralizan |
| **XSS** en el panel (descripciones con `<script>`) | JSON escapado + todo se pinta con `textContent` |
| Ejecución de scripts no autorizados | **Content-Security-Policy** con hash SHA-256 del script |
| CDN comprometido | Chart.js con versión fija y **Subresource Integrity** (SRI) |
| Exfiltración por webhook falso | Solo se acepta `https://discord.com/api/webhooks/...` |
| Spam de menciones | Las alertas no pueden hacer `@everyone` (`allowed_mentions` vacío) |

## Pruebas

```bash
pytest -v
```

Usan respuestas de ejemplo en `tests/fixtures/` (no necesitan internet): fechas, paginación,
reintentos, consolidación, fórmula de prioridad, cruce de inventario, escape anti-XSS del panel,
hash CSP, validación del webhook y que el Excel/CSV se generen bien.

## Limitaciones

- **NVD sin llave:** ~5 solicitudes cada 30 s. 5 años (~150 000 CVE) toman ~10 min; con llave ~1–2 min.
- **GitHub sin token:** 60 solicitudes/hora. Si se agota, se exporta lo obtenido y se avisa.
- El cruce con el inventario es por nombre de proveedor/producto, no por versión.
- El índice de prioridad es una ayuda para decidir, no reemplaza el análisis del contexto de cada activo.

## Autor

Wilfelix Estevez Hernandez — Técnico Superior en Ciberseguridad
