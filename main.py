"""Punto de entrada de CVE Explorer.

Uso rápido:
    python main.py            -> menú interactivo
    python main.py --help     -> todas las opciones
"""

import sys

from cve_explorer.cli import main

if __name__ == "__main__":
    sys.exit(main())
