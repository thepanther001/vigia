# CVE Explorer

Programa en Python que **consulta vulnerabilidades CVE en varias bases de datos**,
permite elegir el **rango de fechas (dentro de los últimos 5 años)** y las **fuentes**,
y **exporta** los resultados a **Excel** (con tablas y gráficos) y a **CSV listos para Power BI**.

![Python](https://img.shields.io/badge/python-3.10%2B-blue) ![Licencia](https://img.shields.io/badge/licencia-MIT-green)

---

## Bases de datos soportadas

| Clave | Fuente | Qué aporta | Filtro de fecha | Llave |
|---|---|---|---|---|
| `nvd` | [NVD – NIST](https://nvd.nist.gov) | Catálogo oficial de CVE: CVSS v2/v3/v4, CWE, productos afectados (CPE) | Fecha de publicación | Opcional (`NVD_API_KEY`) |
| `kev` | [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | CVE **explotadas activamente**, uso en ransomware, fecha límite de parcheo | Fecha en que CISA la agregó | No |
| `ghsa` | [GitHub Advisory Database](https://github.com/advisories) | Vulnerabilidades en librerías (npm, pip, Maven, NuGet…) | Fecha de publicación | Opcional (`GITHUB_TOKEN`) |
| *extra* | [EPSS – FIRST](https://www.first.org/epss) | Probabilidad de explotación en 30 días (`--epss`) | — | No |

Cuando una misma CVE aparece en varias fuentes, el programa la **consolida en una sola fila**
tomando lo mejor de cada una (CVSS de la NVD, nombre y proveedor de CISA, paquete de GitHub).

---

## Inicio rápido en GitHub Codespaces (recomendado)

1. En el repositorio: **Code → Codespaces → Create codespace on main**.
2. Esperar a que instale las dependencias (lo hace solo, ver `.devcontainer/`).
3. En la terminal:

```bash
python main.py
```

> En Codespaces la variable `GITHUB_TOKEN` ya existe, así que la fuente de GitHub funciona a velocidad completa.

## Instalación local

```bash
git clone https://github.com/<tu-usuario>/cve-explorer.git
cd cve-explorer
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env               # opcional: poner las llaves
```

### Llave de la NVD (gratis, muy recomendada)

Sin llave la NVD permite ~5 solicitudes cada 30 s; con llave, ~50.
Se pide en <https://nvd.nist.gov/developers/request-an-api-key> y se pone en `.env`:

```
NVD_API_KEY=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
```

---

## Uso

### Menú interactivo

```bash
python main.py
```

```
[1] Rango de fechas (permitido: 2021-10-22 a 2026-10-22)
    1) Últimos 7 días   2) Últimos 30 días   3) Últimos 90 días
    4) Último año       5) Últimos 5 años    6) Personalizado
[2] Bases de datos a consultar
    1) NVD   2) CISA KEV   3) GitHub Advisory
[3] Exportar como  1) Excel + CSV   2) Solo Excel   3) Solo CSV
```

### Con parámetros

```bash
# Últimos 30 días en todas las fuentes
python main.py --ultimos-dias 30 --fuentes todas

# Rango exacto, solo NVD y CISA KEV
python main.py --desde 2025-01-01 --hasta 2025-06-30 --fuentes nvd,kev

# Todo lo que CISA marcó como explotado en 2024, solo Excel
python main.py --desde 2024-01-01 --hasta 2024-12-31 --fuentes kev --formato excel

# Prueba rápida con EPSS y máximo 500 registros por fuente
python main.py --ultimos-dias 7 --fuentes nvd,ghsa --epss --limite 500

# Ver fuentes y ayuda
python main.py --listar-fuentes
python main.py --help
```

| Opción | Descripción |
|---|---|
| `--desde`, `--hasta` | Rango `AAAA-MM-DD` (máximo 5 años hacia atrás; `--hasta` por defecto es hoy) |
| `--ultimos-dias N` | Atajo para los últimos N días |
| `--fuentes` | `nvd`, `kev`, `ghsa` separados por coma, o `todas` |
| `--formato` | `excel`, `csv` o `ambos` (por defecto) |
| `--salida` | Carpeta de salida (por defecto `output/`) |
| `--epss` | Agrega probabilidad de explotación EPSS |
| `--limite N` | Máximo de registros por fuente (para pruebas) |
| `--idioma es\|en` | Idioma preferido de las descripciones de la NVD |
| `--incluir-sin-cve` | Incluye avisos de GitHub sin CVE asignado |

### Desde la pestaña Actions (sin instalar nada)

**Actions → Generar reporte CVE → Run workflow**, llenar fechas y fuentes.
Al terminar, el Excel y los CSV quedan en **Artifacts → reporte-cve**.
(Opcional: guardar la llave en **Settings → Secrets → Actions → `NVD_API_KEY`**.)

---

## Qué se genera

```
output/
├── cve_20250101_20250630_20261022-151516.xlsx   ← reporte Excel (uno por corrida)
└── powerbi/                                      ← CSV para Power BI (se sobrescriben)
    ├── consolidado.csv     una fila por CVE
    ├── registros.csv       una fila por CVE y fuente
    ├── cwe_por_cve.csv     una fila por CVE y CWE
    └── por_mes.csv         conteo mensual por fuente
```

### Hojas del Excel

| Hoja | Contenido |
|---|---|
| **Resumen** | Indicadores (CVE únicas, críticas, altas, explotadas, ransomware, CVSS promedio) y 4 gráficos |
| **Consolidado** | Tabla filtrable, una fila por CVE, severidad con colores |
| **Registros** | Datos tal cual los reporta cada fuente |
| **Por_Mes** | Tendencia mensual por fuente |
| **Por_Severidad** | Cantidad y porcentaje por severidad |
| **Top_Proveedores** | Proveedores con más CVE, críticas y explotadas |
| **Top_CWE** | Tipos de debilidad más comunes (con nombre en español) |
| **Parametros** | Rango, fuentes, resultado de cada consulta y advertencias |

Para Power BI ver **[docs/GUIA_POWER_BI.md](docs/GUIA_POWER_BI.md)** (importación, relaciones, medidas DAX y visuales).

---

## Estructura del proyecto

```
cve-explorer/
├── main.py                       punto de entrada
├── cve_explorer/
│   ├── cli.py                    menú interactivo y parámetros
│   ├── config.py                 llaves y ajustes (lee .env)
│   ├── fechas.py                 validación de 5 años y división en tramos
│   ├── modelo.py                 registro común y normalización de severidad
│   ├── cliente_http.py           GET con reintentos y control de límites
│   ├── fuentes/
│   │   ├── base.py               clase base (para agregar más fuentes)
│   │   ├── nvd.py                NVD API 2.0
│   │   ├── cisa_kev.py           catálogo CISA KEV
│   │   └── github_advisory.py    GitHub Advisory Database
│   ├── epss.py                   enriquecimiento EPSS (opcional)
│   ├── procesamiento.py          consolidación y tablas resumen (pandas)
│   └── exportar.py               Excel con formato/gráficos y CSV
├── tests/                        pruebas con datos de ejemplo (sin internet)
├── docs/GUIA_POWER_BI.md
├── .devcontainer/                configuración de Codespaces
└── .github/workflows/            pruebas automáticas y reporte bajo demanda
```

### Cómo funciona

```
Usuario ─► cli.py ─► valida fechas (fechas.py)
                  └► por cada fuente elegida: consultar(desde, hasta)
                         NVD:    tramos de 120 días × páginas de 2000
                         KEV:    descarga el catálogo y filtra por dateAdded
                         GitHub: páginas de 100 con cursor (encabezado Link)
                  └► procesamiento.py: DataFrame → consolidado por CVE → resúmenes
                  └► exportar.py: Excel + CSV
```

### Agregar otra base de datos

1. Crear `cve_explorer/fuentes/mi_fuente.py` con una clase que herede de `FuenteBase` e implemente `consultar(desde, hasta)` devolviendo una lista de `Registro`.
2. Registrarla en `cve_explorer/fuentes/__init__.py` dentro de `FUENTES`.

---

## Pruebas

```bash
pytest -v
```

Las pruebas usan respuestas de ejemplo en `tests/fixtures/` (no necesitan internet) y cubren:
validación de fechas, paginación, reintentos por límite de velocidad, cuota agotada de GitHub,
consolidación entre fuentes y que el Excel/CSV se generen correctamente.
GitHub Actions las corre en cada `push`.

## Buenas prácticas de seguridad aplicadas

- Las llaves se leen de variables de entorno / `.env`, que está en `.gitignore`.
- Se respetan los límites de cada API (pausas, `Retry-After`, `X-RateLimit-*`) con reintentos exponenciales.
- Los textos se sanean antes de exportar para evitar **inyección de fórmulas** (CSV/Formula Injection, OWASP):
  una descripción que empiece con `=`, `+`, `-` o `@` no se ejecuta al abrirla en Excel.
- Solo lectura sobre APIs públicas oficiales; no se escanea ni se toca ningún sistema.

## Limitaciones

- **Velocidad de la NVD:** 5 años son ~150 000 CVE → ~80 solicitudes. Sin llave toma ~10 min; con llave ~1–2 min.
- **GitHub sin token:** 60 solicitudes/hora (≈6000 avisos). Si se agota, se exporta lo obtenido y se avisa.
- **CISA KEV** no trae CVSS; si se consulta sola, la severidad sale "SIN CALIFICAR". Combinarla con `nvd` para tenerla.
- Las fechas de cada fuente no significan lo mismo (publicación vs. agregada al catálogo); se indica en la hoja *Parametros*.

## Autor

Wilfelix Estevez Hernandez — Técnico Superior en Ciberseguridad
