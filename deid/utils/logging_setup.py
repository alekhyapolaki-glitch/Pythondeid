"""Console + rotating file logging."""

from __future__ import annotations

import logging
import logging.handlers
from pathlib import Path


def setup_logging(level: str = "INFO", log_dir: str = "logs", name: str = "deid") -> Path:
    Path(log_dir).mkdir(parents=True, exist_ok=True)
    log_file = Path(log_dir) / ("%s.log" % name)
    root = logging.getLogger()
    root.handlers.clear()
    root.setLevel(logging.DEBUG)

    console = logging.StreamHandler()
    console.setLevel(getattr(logging, str(level).upper(), logging.INFO))
    console.setFormatter(logging.Formatter("%(asctime)s %(levelname)-7s %(message)s", "%H:%M:%S"))
    root.addHandler(console)

    fh = logging.handlers.RotatingFileHandler(log_file, maxBytes=10 * 1024 * 1024, backupCount=10, encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter("%(asctime)s %(levelname)-7s [%(name)s] %(message)s"))
    root.addHandler(fh)
    return log_file
