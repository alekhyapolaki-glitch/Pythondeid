"""Shared config helpers: errors, project root, YAML reading and dict merging."""

from __future__ import annotations

import copy
import os
from pathlib import Path
from typing import Any, Dict

try:
    import yaml
except ImportError:  # PyYAML-ft (free-threading build, e.g. some ActiveState runtimes)
    import yaml_ft as yaml


class ConfigError(Exception):
    pass


PROJECT_ROOT = Path(__file__).resolve().parents[2]  # deid/config/base.py -> project folder


def _deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    out = copy.deepcopy(base)
    for k, v in (override or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def _read_yaml(path: Path) -> Dict[str, Any]:
    if not path.exists():
        raise ConfigError("Config file not found: %s" % path)
    try:
        with path.open("r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
    except yaml.YAMLError as exc:
        raise ConfigError("Invalid YAML in %s: %s" % (path, exc)) from exc
    if not isinstance(data, dict):
        raise ConfigError("%s must contain a mapping at the top level" % path)
    return data


def _resolve(path_value: str) -> str:
    p = Path(os.path.expandvars(str(path_value)))
    return str(p if p.is_absolute() else PROJECT_ROOT / p)
