"""PyInstaller entry point (packaging/windows/entry.py): redoubt uses relative imports, so it must be started as a package"""
import multiprocessing
from redoubt.app import main

if __name__ == "__main__":
    multiprocessing.freeze_support()    # harmless if unused, required if any dependency spawns processes
    raise SystemExit(main())
