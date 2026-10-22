"""Configuración general del programa.

Las llaves de API se leen de variables de entorno o de un archivo .env
en la raíz del proyecto (ver .env.example). Nunca se escriben en el código.
"""

import os

try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:  # python-dotenv es opcional
    pass

from cve_explorer import __version__

# Identificación del programa ante las APIs (buena práctica: no ir "anónimo").
USER_AGENT = f"CVE-Explorer/{__version__} (proyecto academico; python-requests)"

# Tiempo máximo de espera por solicitud HTTP (segundos).
TIMEOUT = 60

# Regla de la tarea: solo se permite consultar dentro de los últimos 5 años.
MAX_ANIOS = 5

# Llaves opcionales (aumentan los límites de velocidad de cada API).
NVD_API_KEY = os.getenv("NVD_API_KEY") or None
# En GitHub Codespaces la variable GITHUB_TOKEN ya existe automáticamente.
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN") or os.getenv("GH_TOKEN") or None

# Carpeta de salida por defecto.
CARPETA_SALIDA = "output"
