# Seguridad

Vigía es una herramienta de ciberseguridad, así que también se cuida a sí misma.

## Reportar un problema

Si encuentras una vulnerabilidad en Vigía, **no abras un issue público**.
Usa **Security → Report a vulnerability** en este repositorio (aviso privado).
Se responde en un máximo de 7 días.

## Qué protege el proyecto

| Riesgo | Control |
|---|---|
| Llaves expuestas | Solo por variables de entorno, `.env` (ignorado por git) y GitHub Secrets |
| Datos externos maliciosos en el panel (XSS) | JSON escapado, todo se pinta con `textContent`, CSP con hash del script |
| Scripts de terceros | El panel no carga ningún script externo |
| Inyección de fórmulas en Excel/CSV | Textos que empiezan con `= + - @` se neutralizan |
| Archivos de Excel dañados | Se eliminan caracteres que XML no permite |
| Envío de datos a destinos falsos | El webhook de Discord solo acepta `discord.com/api/webhooks` |
| Dependencias vulnerables | Versiones fijas, Dependabot semanal y `pip-audit` en cada push |
| Código inseguro | `bandit` y GitHub CodeQL en cada push |
| Workflows con demasiados permisos | Permisos mínimos por workflow; sin credenciales guardadas tras el checkout |
| Inyección en workflows | Las entradas del usuario pasan por variables de entorno, nunca dentro del script |

## Uso responsable de los datos

El panel en GitHub Pages es **público**. El inventario incluido es de una **empresa ficticia**.
Nunca publiques el inventario real de una organización: le diría a un atacante qué software
vulnerable tiene. Para uso real: repositorio privado, o `--sin-inventario` en el panel público.

Vigía solo **lee** fuentes públicas oficiales (NVD, CISA, GitHub, FIRST). No escanea ni toca ningún sistema.
