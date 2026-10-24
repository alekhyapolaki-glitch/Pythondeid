"""settings.yaml: how the tool runs (security, execution, batching, audit, logging). The selected
connection and the paths are attached to the Settings object at load time."""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from .base import ConfigError, _deep_merge, _read_yaml, _resolve, yaml
from .copy_map import MODES
from .connections import DEFAULT_CONNECTION, load_connections, validate_connection
from .paths import load_paths

SECRET_KEY_ENV_DEFAULT = "DEID_SECRET_KEY"  # noqa: S105  # nosec B105


DEFAULT_SETTINGS: Dict[str, Any] = {
    "security": {"secret_key_env": SECRET_KEY_ENV_DEFAULT, "min_key_length": 32, "expected_key_fingerprint": ""},
    "execution": {
        "mode": "in_place",              # in_place = UPDATE the database | on_the_fly = read, mask, write a target
        "batch_size": "auto",            # rows per chunk, or "auto" = sized per table (see batching below)
        "fetch_size": 20000,
        "workers": "auto",               # masking processes: "auto" = CPU count - 1 (max 8), or a number
        "disable_unique_indexes": True,  # allow batched updates of masked columns with unique NC indexes
        "disable_triggers": True,
        "auto_include_fk_columns": True,
        "stop_on_error": True,
        "collision_check": True,
        "max_retries": 3,
        "retry_backoff_seconds": 2,
        "collision_check_max_values": 5000000,
        "allow_single_statement_rows": 50000000,
        "type_mismatch": "error",        # expected_input_type differs from the live column: error | warn
    },
    "batching": {                        # used when execution.batch_size = auto
        "target_batch_mb": 256,          # approx. data rewritten (and logged) per committed chunk
        "min_batch_size": 10000,
        "max_batch_size": 500000,
    },
    "audit": {"write_to_db": True, "schema": "deid_audit"},
    "logging": {"level": "INFO"},
}


_SECTIONS = ("security", "execution", "batching", "audit", "logging")


_LEGACY_SECTIONS = ("database",)  # older settings.yaml kept the connection here; still accepted


@dataclass
class Settings:
    database: Dict[str, Any]
    security: Dict[str, Any]
    execution: Dict[str, Any]
    batching: Dict[str, Any]
    audit: Dict[str, Any]
    logging: Dict[str, Any]
    source_path: Optional[Path] = None
    paths: Dict[str, str] = field(default_factory=dict)
    connection_name: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """settings.yaml content: behaviour only (connections and paths live in their own files)."""
        out = {k: copy.deepcopy(getattr(self, k)) for k in _SECTIONS}
        out["audit"].pop("output_dir", None)
        out["logging"].pop("dir", None)
        return out


def load_settings(path: str, connections_path: Optional[str] = None, connection: Optional[str] = None,
                  paths_path: Optional[str] = None) -> Settings:
    p = Path(path)
    raw = _read_yaml(p) if p.exists() else {}
    unknown = set(raw) - set(DEFAULT_SETTINGS) - set(_LEGACY_SECTIONS)
    if unknown:
        raise ConfigError("Unknown section(s) in %s: %s" % (p, sorted(unknown)))
    legacy_db = raw.pop("database", None)
    merged = _deep_merge(DEFAULT_SETTINGS, raw)
    paths = _resolve_paths(merged, paths_path)
    name, db = _resolve_connection(connections_path, connection, legacy_db, p)
    _check_execution(merged["execution"])
    _check_batching(merged["batching"])
    if not str(merged["audit"]["schema"]).replace("_", "").isalnum():
        raise ConfigError("audit.schema must be a simple identifier")
    return Settings(database=db, source_path=p, paths=paths, connection_name=name, **merged)


def _resolve_paths(merged: Dict[str, Any], paths_path: Optional[str]) -> Dict[str, Any]:
    """paths.yaml decides where files go; older settings.yaml values are honoured when paths.yaml is absent."""
    paths = load_paths(paths_path)
    if not (paths_path and Path(paths_path).exists()):
        if merged["audit"].get("output_dir"):
            paths["audit_dir"] = _resolve(merged["audit"]["output_dir"])
        if merged["logging"].get("dir"):
            paths["log_dir"] = _resolve(merged["logging"]["dir"])
    merged["audit"]["output_dir"] = paths["audit_dir"]
    merged["logging"]["dir"] = paths["log_dir"]
    return paths


def _resolve_connection(connections_path: Optional[str], connection: Optional[str], legacy_db: Any,
                        settings_path: Path) -> Tuple[str, Dict[str, Any]]:
    """(connection name, connection settings): connections.yaml, else a legacy settings.yaml section, else defaults."""
    if connections_path and Path(connections_path).exists():
        default, conns = load_connections(connections_path)
        name = connection or default
        if name not in conns:
            raise ConfigError("Connection '%s' is not in %s (available: %s). Add it with: python main.py configure"
                              % (name, connections_path, ", ".join(conns) or "none"))
        return name, conns[name]
    if connection:
        raise ConfigError("--connection %s given but %s does not exist; run: python main.py configure"
                          % (connection, connections_path))
    if legacy_db is not None:
        return "settings.yaml", validate_connection(legacy_db, "%s database" % settings_path)
    return "", dict(DEFAULT_CONNECTION)


def _check_execution(ex: Dict[str, Any]) -> None:
    for k in ("fetch_size", "max_retries", "collision_check_max_values"):
        if not isinstance(ex[k], int) or ex[k] < (0 if k == "max_retries" else 1):
            raise ConfigError("execution.%s must be a positive integer" % k)
    for k in ("batch_size", "workers"):
        if ex[k] != "auto" and (not isinstance(ex[k], int) or ex[k] < 1):
            raise ConfigError("execution.%s must be 'auto' or a positive integer" % k)
    if ex["mode"] not in MODES:
        raise ConfigError("execution.mode must be one of %s" % ", ".join(MODES))
    if ex["type_mismatch"] not in ("error", "warn"):
        raise ConfigError("execution.type_mismatch must be 'error' or 'warn'")


def _check_batching(b: Dict[str, Any]) -> None:
    for k in ("target_batch_mb", "min_batch_size", "max_batch_size"):
        if not isinstance(b[k], int) or b[k] < 1:
            raise ConfigError("batching.%s must be a positive integer" % k)
    if b["min_batch_size"] > b["max_batch_size"]:
        raise ConfigError("batching.min_batch_size must be <= max_batch_size")


def save_settings(settings: Settings, path: str) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("# How the tool runs. Connections: connections.yaml. File locations: paths.yaml.\n")
        yaml.safe_dump(settings.to_dict(), fh, sort_keys=False, default_flow_style=False)
