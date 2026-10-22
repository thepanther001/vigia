"""Permite ejecutar el programa con:  python -m cve_explorer"""

import sys

from cve_explorer.cli import main

if __name__ == "__main__":
    sys.exit(main())
