"""connections.yaml: named database connections (per machine; no passwords)."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Tuple

from .base import ConfigError, _deep_merge, _read_yaml, yaml

# Names of environment variables (not secrets themselves).
PASSWORD_ENV_DEFAULT = "DEID_DB_PASSWORD"  # noqa: S105  # nosec B105


DEFAULT_CONNECTION: Dict[str, Any] = {
    "driver": "ODBC Driver 18 for SQL Server",
    "server": "localhost",
    "database": "",
    "auth": "windows",  # windows | sql | azure_ad_interactive | azure_ad_password
    "username": "",
    "password_env": PASSWORD_ENV_DEFAULT,
    "encrypt": True,
    "trust_server_certificate": False,
    "login_timeout": 30,
    "query_timeout": 0,
    "application_name": "pythondeid",
    "extra": {},
}


_AUTH_MODES = ("windows", "sql", "azure_ad_interactive", "azure_ad_password")


def validate_connection(db: Dict[str, Any], where: str) -> Dict[str, Any]:
    unknown = set(db) - set(DEFAULT_CONNECTION)
    if "password" in db:
        raise ConfigError("%s: do not store passwords in config files. Put it in the environment variable named by "
                          "password_env (default DEID_DB_PASSWORD)." % where)
    if unknown:
        raise ConfigError("%s: unknown key(s) %s. Allowed: %s" % (where, sorted(unknown), sorted(DEFAULT_CONNECTION)))
    merged = _deep_merge(DEFAULT_CONNECTION, db)
    if merged["auth"] not in _AUTH_MODES:
        raise ConfigError("%s: auth must be one of %s" % (where, ", ".join(_AUTH_MODES)))
    if merged["auth"] in ("sql", "azure_ad_password", "azure_ad_interactive") and not merged["username"]:
        raise ConfigError("%s: username is required for auth=%s" % (where, merged["auth"]))
    return merged


def load_connections(path: str) -> Tuple[str, Dict[str, Dict[str, Any]]]:
    """Returns (default name, {name: connection}) from connections.yaml."""
    raw = _read_yaml(Path(path))
    conns = raw.get("connections") or {}
    if not isinstance(conns, dict):
        raise ConfigError("%s: 'connections' must be a mapping of name -> connection settings" % path)
    unknown = set(raw) - {"default", "connections"}
    if unknown:
        raise ConfigError("Unknown key(s) in %s: %s (expected 'default' and 'connections')" % (path, sorted(unknown)))
    out = {str(n): validate_connection(c or {}, "%s connection '%s'" % (path, n)) for n, c in conns.items()}
    default = str(raw.get("default") or (next(iter(out)) if out else ""))
    if out and default not in out:
        raise ConfigError("%s: default connection '%s' is not defined" % (path, default))
    return default, out


def save_connection(path: str, name: str, db: Dict[str, Any], make_default: bool) -> None:
    p = Path(path)
    raw = _read_yaml(p) if p.exists() else {}
    conns = raw.get("connections") or {}
    conns[name] = {k: v for k, v in db.items() if k in DEFAULT_CONNECTION}
    default = name if (make_default or not raw.get("default")) else raw["default"]
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w", encoding="utf-8") as fh:
        fh.write("# Database connections for this machine (no passwords: use the password_env variable).\n"
                 "# Pick one with --connection NAME; otherwise 'default' is used. Not committed to Git.\n")
        yaml.safe_dump({"default": default, "connections": conns}, fh, sort_keys=False, default_flow_style=False)
