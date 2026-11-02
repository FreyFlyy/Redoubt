### launcher.py

import os
import sys
from redoubt.app import main

# Forza UTF-8 per l'I/O standard su Windows per evitare problemi con i font e i caratteri speciali
if sys.platform == "win32":
    os.environ["PYTHONIOENCODING"] = "utf-8"
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8")

if __name__ == "__main__":
    main()
