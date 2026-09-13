"""`python -m services.harness ...` -> `services.harness.cli:main`.

Thin on purpose: the module-level entry point exists so the documented invocation works, and every
decision lives in `cli.py` where it can be imported and tested without a subprocess.
"""

from __future__ import annotations

import sys

from services.harness.cli import main

if __name__ == "__main__":
    sys.exit(main())
