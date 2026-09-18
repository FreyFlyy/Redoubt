### logger.py

"""
Logging module for Redoubt

Typical usage:
    from . import logger as logger_mod
    logger = logger_mod.get_logger(__name__)
    ...
    try:
        ...
    except Exception:
        logger.exception("Error...")
"""

import os
import logging


## Define log dir and file

LOG_DIR = os.path.join(os.path.expanduser("~"), ".redoubt")
LOG_FILE = os.path.join(LOG_DIR, "redoubt.log")

_configured = False


## Configure logger and define calling method

def _configure_root():
    """Configure logger file, format and calling scheme"""
    global _configured
    if _configured:
        return

    os.makedirs(LOG_DIR, exist_ok=True)

    handler = logging.FileHandler(LOG_FILE, encoding="utf-8")
    handler.setFormatter(logging.Formatter(
        fmt="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    ))

    root = logging.getLogger("redoubt")
    root.setLevel(logging.INFO)
    root.addHandler(handler)
    root.propagate = False  # Don't propagate to python logger

    _configured = True

def get_logger(name: str) -> logging.Logger:
    """To call as get_logger(__name__) in every module that needs logging"""
    _configure_root()
    return logging.getLogger(f"redoubt.{name}")
