"""paths.yaml: file and folder locations, resolved relative to the project folder."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Optional

from .base import ConfigError, _read_yaml, _resolve

DEFAULT_PATHS: Dict[str, str] = {
    "rules_file": "config/deid_rules.yaml",
    "audit_dir": "audit",
    "log_dir": "logs",
    "discovery_csv": "config/discovered_schema.csv",
    "test_vectors": "config/test_vectors.csv",
    "recommendations_csv": "config/recommendations.csv",
    "file_rules": "config/file_rules.yaml",
    "file_input_dir": "data/input",
    "file_output_dir": "data/output",
    "profiles_dir": "config/profiles",
    "run_results_dir": "audit/results",
}


def load_paths(path: Optional[str] = None) -> Dict[str, str]:
    """File/folder locations from paths.yaml (defaults when the file is absent), as absolute paths."""
    raw: Dict[str, Any] = {}
    if path and Path(path).exists():
        raw = _read_yaml(Path(path))
        unknown = set(raw) - set(DEFAULT_PATHS)
        if unknown:
            raise ConfigError("Unknown key(s) in %s: %s. Allowed: %s" % (path, sorted(unknown), sorted(DEFAULT_PATHS)))
    merged = dict(DEFAULT_PATHS, **{k: str(v) for k, v in raw.items() if v})
    return {k: _resolve(v) for k, v in merged.items()}
