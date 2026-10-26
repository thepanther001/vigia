# Guía: Vigía en Power BI

Power BI se conecta **directo al panel publicado**. Los CSV se regeneran cada mañana,
así que el reporte se actualiza con un clic, sin correr nada.

| Archivo | URL | Una fila por… |
|---|---|---|
| Consolidado | `https://thepanther001.github.io/vigia/powerbi/consolidado.csv` | CVE (tabla principal) |
| Registros | `https://thepanther001.github.io/vigia/powerbi/registros.csv` | CVE y fuente |
| Inventario | `https://thepanther001.github.io/vigia/powerbi/inventario_afectaciones.csv` | Activo y CVE |
| Debilidades | `https://thepanther001.github.io/vigia/powerbi/cwe_por_cve.csv` | CVE y CWE |

> ¿Sin internet o con datos propios? Corre `python main.py ...` y usa los CSV de `output/powerbi/` con **Obtener datos → Texto o CSV**.

## 1. Importar

1. Instala **Power BI Desktop** (gratis, Microsoft Store).
2. **Inicio → Obtener datos → Web** → pega la URL de *Consolidado* → **Aceptar** → **Transformar datos**.
3. Revisa los tipos de columna (ícono a la izquierda del nombre):

| Columna | Tipo |
|---|---|
| `fecha_publicacion`, `fecha_limite_cisa` | Fecha |
| `cvss_puntaje`, `epss`, `epss_percentil`, `prioridad_puntaje` | Número decimal |
| `severidad_orden`, `anio`, `num_fuentes` | Número entero |
| `explotada_activamente`, `en_nvd`, `en_kev`, `en_github` | Verdadero/Falso |

   Si un decimal sale mal (9.8 aparece como 98): clic derecho en la columna →
   **Cambiar tipo → Usar configuración regional → Número decimal / Inglés (Estados Unidos)**.
4. Repite con *Registros*, *Inventario* y *Debilidades* → **Cerrar y aplicar**.

## 2. Tema de Vigía

**Vista → Temas → Buscar temas** → elige `docs/powerbi/vigia-tema.json`.
Aplica los colores de la marca, la fuente Inter y el fondo del panel.

## 3. Relaciones

En la vista **Modelo** arrastra:

- `consolidado[cve_id]` → `registros[cve_id]`
- `consolidado[cve_id]` → `inventario_afectaciones[cve_id]`
- `consolidado[cve_id]` → `cwe_por_cve[cve_id]`

## 4. Columnas y medidas (Modelado → Nueva columna / Nueva medida)

Orden lógico de los plazos (para que no salgan en orden alfabético):

```DAX
Orden plazo =
SWITCH ( consolidado[prioridad_nivel],
    "INMEDIATA", 1, "URGENTE", 2, "PLANIFICADA", 3, "RUTINA", 4, 5 )
```

Selecciona `prioridad_nivel` → **Herramientas de columnas → Ordenar por columna → Orden plazo**.
Haz lo mismo con `severidad` → ordenar por `severidad_orden`.

```DAX
Total CVE = DISTINCTCOUNT ( consolidado[cve_id] )

Corrección inmediata = CALCULATE ( [Total CVE], consolidado[prioridad_nivel] = "INMEDIATA" )

Explotadas = CALCULATE ( [Total CVE], consolidado[explotada_activamente] = TRUE () )

Críticas = CALCULATE ( [Total CVE], consolidado[severidad] = "CRÍTICA" )

Afectan inventario = CALCULATE ( [Total CVE], NOT ISBLANK ( consolidado[activos_afectados] ) )

CVSS promedio = AVERAGE ( consolidado[cvss_puntaje] )

Índice promedio = AVERAGE ( consolidado[prioridad_puntaje] )
```

## 5. Página sugerida (igual al panel web)

| Zona | Visual | Campos |
|---|---|---|
| Arriba | Tarjeta grande | **Corrección inmediata** (color naranja `#EB6834`) |
| Arriba derecha | 4 tarjetas pequeñas | Total CVE, Explotadas, Críticas, Afectan inventario |
| Centro | Gráfico de columnas | Eje: `fecha_publicacion` (día) · Valores: Total CVE |
| Centro | Gráfico de líneas sobre las columnas, o columna aparte | `registros` filtrado a fuente = CISA KEV |
| Izquierda | Tabla "Qué corregir primero" | `prioridad_puntaje`, `prioridad_nivel`, `cve_id`, `titulo`, `cvss_puntaje`, `epss`, `explotada_activamente` · ordenada por `prioridad_puntaje` ↓ · Top N = 20 |
| Derecha | Barras horizontales | Eje: `inventario_afectaciones[activo]` · Valores: Total CVE |
| Abajo | Barra 100 % apilada | Leyenda: `severidad` · Valores: Total CVE |
| Abajo | Barras | `proveedor` (Top 10) y `cwe_por_cve[nombre_cwe]` (Top 10) |
| Lateral | Segmentadores | `fecha_publicacion`, `prioridad_nivel`, `severidad`, `explotada_activamente` |

Colores con significado (iguales al panel):

- **Naranja `#EB6834` solo para lo que se está explotando** o es de corrección inmediata.
- Severidad en azules: Crítica `#1B2B48` · Alta `#2A5FA8` · Media `#4F8FDB` · Baja `#A9C8EE`.
- Plazos: Inmediata `#EB6834` · Urgente `#2A78D6` · Planificada `#8DA9CF` · Rutina `#C3CAD5`.

Para que `url` sea un enlace: selecciona la columna → **Categoría de datos → Dirección URL web**.

## 6. Actualizar

**Inicio → Actualizar.** Power BI vuelve a leer los CSV del panel, que GitHub Actions regenera cada mañana a las 7:17 a. m.
