# Guía: visualizar los datos en Power BI

El programa deja los CSV en `output/powerbi/` y **siempre con el mismo nombre**,
así el reporte de Power BI se actualiza con un clic después de cada consulta.

| Archivo | Una fila por… | Uso |
|---|---|---|
| `consolidado.csv` | CVE | Tabla principal (hechos) |
| `registros.csv` | CVE y fuente | Comparar qué reporta cada base |
| `cwe_por_cve.csv` | CVE y CWE | Analizar tipos de debilidad |
| `por_mes.csv` | Mes | Tendencia ya calculada (opcional) |

## 1. Importar

1. **Obtener datos → Texto o CSV** → elegir `consolidado.csv` → **Transformar datos**.
2. Revisar tipos en Power Query:

| Columna | Tipo |
|---|---|
| `fecha_publicacion`, `fecha_limite_cisa` | Fecha |
| `cvss_puntaje`, `epss`, `epss_percentil` | Número decimal |
| `severidad_orden`, `anio`, `num_fuentes` | Número entero |
| `explotada_activamente`, `en_nvd`, `en_kev`, `en_github` | Verdadero/Falso |

3. Repetir con `registros.csv` y `cwe_por_cve.csv` → **Cerrar y aplicar**.

> Si Power BI está en español y lee mal los decimales (9.8 → 98): en Power Query,
> clic derecho en la columna → **Cambiar tipo → Usar configuración regional → Inglés (Estados Unidos)**.

## 2. Modelo (relaciones)

En la vista **Modelo** arrastrar:

- `consolidado[cve_id]` (1) → `registros[cve_id]` (*)
- `consolidado[cve_id]` (1) → `cwe_por_cve[cve_id]` (*)

Para que la severidad salga en orden lógico: seleccionar `consolidado[severidad]` →
**Herramientas de columnas → Ordenar por columna → `severidad_orden`**.

## 3. Medidas DAX

```DAX
Total CVE = DISTINCTCOUNT ( consolidado[cve_id] )

CVE Críticas = CALCULATE ( [Total CVE], consolidado[severidad] = "CRÍTICA" )

CVE Explotadas = CALCULATE ( [Total CVE], consolidado[explotada_activamente] = TRUE () )

% Explotadas = DIVIDE ( [CVE Explotadas], [Total CVE] )

CVSS Promedio = AVERAGE ( consolidado[cvss_puntaje] )

Ransomware = CALCULATE ( [Total CVE], consolidado[ransomware] = "Sí" )
```

## 4. Visuales sugeridos

| Visual | Campos |
|---|---|
| Tarjetas | Total CVE, CVE Críticas, CVE Explotadas, CVSS Promedio |
| Gráfico de líneas | Eje: `fecha_publicacion` (jerarquía Año/Mes) · Valores: Total CVE · Leyenda: `registros[fuente]` |
| Anillo | Leyenda: `severidad` · Valores: Total CVE |
| Barras horizontales | Eje: `proveedor` · Valores: Total CVE (Top N = 10 en el panel de filtros) |
| Barras | Eje: `cwe_por_cve[nombre_cwe]` · Valores: Total CVE |
| Tabla | `cve_id`, `titulo`, `severidad`, `cvss_puntaje`, `proveedor`, `explotada_activamente`, `url` |
| Segmentadores | `fecha_publicacion` (rango), `severidad`, `fuentes`, `explotada_activamente` |

Para que la columna `url` sea clicable: seleccionarla → **Categoría de datos → Dirección URL web**.

## 5. Actualizar con datos nuevos

1. Correr otra vez el programa (`python main.py ...`).
2. En Power BI: **Inicio → Actualizar**.

## 6. Conectar Power BI directo al panel en GitHub Pages (sin bajar archivos)

El workflow **Panel diario** publica los CSV todos los días. En Power BI:

1. **Obtener datos → Web** → pegar
   `https://TU_USUARIO.github.io/vigia/powerbi/consolidado.csv`
2. Repetir con `registros.csv`, `cwe_por_cve.csv` e `inventario_afectaciones.csv`.
3. Cada vez que le des a **Actualizar**, Power BI trae los datos de ese día.

Medidas extra para la prioridad:

```DAX
CVE Inmediatas = CALCULATE ( [Total CVE], consolidado[prioridad_nivel] = "INMEDIATA" )

Prioridad Promedio = AVERAGE ( consolidado[prioridad_puntaje] )

Afectan Inventario = CALCULATE ( [Total CVE], NOT ISBLANK ( consolidado[activos_afectados] ) )
```
