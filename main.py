"""Punto de entrada de Vigía.

Uso rápido:
    python main.py            -> menú interactivo
    python main.py --help     -> todas las opciones
"""

import sys

from vigia.cli import main

if __name__ == "__main__":
    sys.exit(main())
