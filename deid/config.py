"""Loading and validation of settings.yaml (environment) and deid_rules.yaml (what to mask)."""

from __future__ import annotations

import copy
import csv
import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml

from .maskers import MaskerError, get_masker_class


class ConfigError(Exception):
    pass


# =============================================================================
# settings.yaml
# =============================================================================
DEFAULT_SETTINGS: Dict[str, Any] = {
    "database": {
        "driver": "ODBC Driver 18 for SQL Server",
        "server": "localhost",
        "database": "",
        "auth": "windows",  # windows | sql | azure_ad_interactive | azure_ad_password
        "username": "",
        "password_env": "DEID_DB_PASSWORD",
        "encrypt": True,
        "trust_server_certificate": False,
        "login_timeout": 30,
        "query_timeout": 0,
        "application_name": "pythondeid",
        "extra": {},
    },
    "security": {"secret_key_env": "DEID_SECRET_KEY", "min_key_length": 32},
    "execution": {
        "batch_size": 50000,
        "fetch_size": 5000,
        "disable_triggers": True,
        "auto_include_fk_columns": True,
        "stop_on_error": True,
        "collision_check": True,
        "max_retries": 3,
        "retry_backoff_seconds": 2,
        "allow_single_statement_rows": 50000000,
    },
    "audit": {"write_to_db": True, "schema": "deid_audit", "output_dir": "audit"},
    "logging": {"level": "INFO", "dir": "logs"},
}

_AUTH_MODES = ("windows", "sql", "azure_ad_interactive", "azure_ad_password")


@dataclass
class Settings:
    database: Dict[str, Any]
    security: Dict[str, Any]
    execution: Dict[str, Any]
    audit: Dict[str, Any]
    logging: Dict[str, Any]
    source_path: Optional[Path] = None

    def to_dict(self) -> Dict[str, Any]:
        return {k: copy.deepcopy(getattr(self, k)) for k in ("database", "security", "execution", "audit", "logging")}


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
        raise ConfigError("Invalid YAML in %s: %s" % (path, exc))
    if not isinstance(data, dict):
        raise ConfigError("%s must contain a mapping at the top level" % path)
    return data


def load_settings(path: str) -> Settings:
    p = Path(path)
    raw = _read_yaml(p)
    unknown = set(raw) - set(DEFAULT_SETTINGS)
    if unknown:
        raise ConfigError("Unknown section(s) in %s: %s" % (p, sorted(unknown)))
    merged = _deep_merge(DEFAULT_SETTINGS, raw)
    db = merged["database"]
    if db["auth"] not in _AUTH_MODES:
        raise ConfigError("database.auth must be one of %s" % (_AUTH_MODES,))
    if db["auth"] in ("sql", "azure_ad_password", "azure_ad_interactive") and not db["username"]:
        raise ConfigError("database.username is required for auth=%s" % db["auth"])
    if "password" in db:
        raise ConfigError(
            "Do not store passwords in settings.yaml. Put it in the environment variable named by "
            "database.password_env (default DEID_DB_PASSWORD)."
        )
    ex = merged["execution"]
    for k in ("batch_size", "fetch_size", "max_retries"):
        if not isinstance(ex[k], int) or ex[k] < (0 if k == "max_retries" else 1):
            raise ConfigError("execution.%s must be a positive integer" % k)
    if not str(merged["audit"]["schema"]).replace("_", "").isalnum():
        raise ConfigError("audit.schema must be a simple identifier")
    return Settings(source_path=p, **merged)


def save_settings(settings: Settings, path: str) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        yaml.safe_dump(settings.to_dict(), fh, sort_keys=False, default_flow_style=False)


# =============================================================================
# deid_rules.yaml
# =============================================================================
@dataclass
class DomainRule:
    """A named masking definition shared by every column that references it."""

    name: str
    type: str
    params: Dict[str, Any] = field(default_factory=dict)

    def signature(self) -> Tuple[str, str]:
        return self.type, json.dumps(self.params, sort_keys=True, default=str)


@dataclass
class ColumnRule:
    name: str
    domain: str


@dataclass
class TableRule:
    schema: str
    table: str
    columns: List[ColumnRule]
    key_columns: List[str] = field(default_factory=list)

    @property
    def fqn(self) -> str:
        return "%s.%s" % (self.schema, self.table)


@dataclass
class Rules:
    domains: Dict[str, DomainRule]
    tables: List[TableRule]
    source_path: Optional[Path] = None
    content_hash: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "domains": {
                d.name: ({"type": d.type, "params": d.params} if d.params else {"type": d.type})
                for d in self.domains.values()
            },
            "tables": [
                dict(
                    {"schema": t.schema, "table": t.table},
                    **({"key_columns": t.key_columns} if t.key_columns else {}),
                    columns=[{"name": c.name, "domain": c.domain} for c in t.columns],
                )
                for t in self.tables
            ],
        }

    def compute_hash(self) -> str:
        blob = json.dumps(self.to_dict(), sort_keys=True, default=str).encode("utf-8")
        return hashlib.sha256(blob).hexdigest()[:16]


def _define_domain(domains: Dict[str, DomainRule], name: str, mtype: str, params: Dict[str, Any], where: str) -> None:
    try:
        cls = get_masker_class(mtype)
        cls.validate_params(params)
    except MaskerError as exc:
        raise ConfigError("%s: %s" % (where, exc))
    new = DomainRule(name, mtype, dict(params))
    old = domains.get(name)
    if old and old.signature() != new.signature():
        raise ConfigError(
            "%s: domain '%s' is already defined as %s %s; one domain must use exactly one masking definition "
            "or referential integrity would break. Use a different domain name." % (where, name, old.type, old.params)
        )
    domains[name] = new


def parse_rules(raw: Dict[str, Any], source: str = "<rules>") -> Rules:
    unknown = set(raw) - {"domains", "tables"}
    if unknown:
        raise ConfigError("Unknown top-level key(s) in %s: %s" % (source, sorted(unknown)))
    domains: Dict[str, DomainRule] = {}
    for name, spec in (raw.get("domains") or {}).items():
        if isinstance(spec, str):
            spec = {"type": spec}
        if not isinstance(spec, dict) or "type" not in spec:
            raise ConfigError("%s: domain '%s' needs a 'type'" % (source, name))
        extra = set(spec) - {"type", "params", "description"}
        if extra:
            raise ConfigError("%s: domain '%s' has unknown key(s) %s" % (source, name, sorted(extra)))
        _define_domain(domains, str(name), spec["type"], spec.get("params") or {}, "%s domain '%s'" % (source, name))

    tables: List[TableRule] = []
    seen_tables = set()
    for i, t in enumerate(raw.get("tables") or []):
        where = "%s tables[%d]" % (source, i)
        if not isinstance(t, dict) or "table" not in t:
            raise ConfigError("%s: each table needs 'table' (and optional 'schema')" % where)
        schema = str(t.get("schema") or "dbo")
        table = str(t["table"])
        key = (schema.lower(), table.lower())
        if key in seen_tables:
            raise ConfigError("%s: table %s.%s listed twice" % (where, schema, table))
        seen_tables.add(key)
        cols: List[ColumnRule] = []
        seen_cols = set()
        for j, c in enumerate(t.get("columns") or []):
            cw = "%s.columns[%d]" % (where, j)
            if isinstance(c, str):
                c = {"name": c}
            if not isinstance(c, dict) or "name" not in c:
                raise ConfigError("%s: column entries need a 'name'" % cw)
            if c["name"].lower() in seen_cols:
                raise ConfigError("%s: column %s listed twice" % (cw, c["name"]))
            seen_cols.add(c["name"].lower())
            if c.get("type"):
                dname = str(c.get("domain") or c["type"])
                _define_domain(domains, dname, c["type"], c.get("params") or {}, cw)
            elif c.get("domain"):
                dname = str(c["domain"])
                if dname not in domains:
                    # Allow referencing a mask type directly as a domain with default params.
                    _define_domain(domains, dname, dname, {}, cw + " (domain '%s' not defined; treated as a mask type)" % dname)
            else:
                raise ConfigError("%s: column '%s' needs a 'domain' or a 'type'" % (cw, c["name"]))
            cols.append(ColumnRule(str(c["name"]), dname))
        if not cols:
            raise ConfigError("%s: table %s.%s has no columns" % (where, schema, table))
        tables.append(TableRule(schema, table, cols, [str(k) for k in (t.get("key_columns") or [])]))

    rules = Rules(domains=domains, tables=tables)
    rules.content_hash = rules.compute_hash()
    return rules


def load_rules(path: str) -> Rules:
    p = Path(path)
    rules = parse_rules(_read_yaml(p), str(p))
    rules.source_path = p
    if not rules.tables:
        raise ConfigError("%s defines no tables to de-identify" % p)
    return rules


def save_rules(rules: Rules, path: str, header: str = "") -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        if header:
            fh.write("".join("# %s\n" % line for line in header.splitlines()))
        yaml.safe_dump(rules.to_dict(), fh, sort_keys=False, default_flow_style=False)


# =============================================================================
# CSV input (table structure + fields) -> rules
# =============================================================================
CSV_COLUMNS = ["schema", "table", "column", "data_type", "max_length", "is_nullable", "is_primary_key",
               "suggested_type", "mask_type", "domain", "params_json"]


def rules_from_csv(path: str) -> Rules:
    """Build rules from a CSV (produced by `discover`, edited in Excel).

    Rows with an empty ``mask_type`` and empty ``domain`` are skipped.
    ``params_json`` may hold a JSON object of masker parameters.
    """
    raw_tables: Dict[Tuple[str, str], Dict[str, Any]] = {}
    with open(path, newline="", encoding="utf-8-sig") as fh:
        reader = csv.DictReader(fh)
        missing = {"table", "column"} - set(reader.fieldnames or [])
        if missing:
            raise ConfigError("%s is missing required column(s): %s" % (path, sorted(missing)))
        for line_no, row in enumerate(reader, start=2):
            mtype = (row.get("mask_type") or "").strip()
            domain = (row.get("domain") or "").strip()
            if not mtype and not domain:
                continue
            params: Dict[str, Any] = {}
            pj = (row.get("params_json") or "").strip()
            if pj:
                try:
                    params = json.loads(pj)
                except ValueError as exc:
                    raise ConfigError("%s line %d: params_json is not valid JSON: %s" % (path, line_no, exc))
            schema = (row.get("schema") or "dbo").strip()
            table = row["table"].strip()
            entry = raw_tables.setdefault((schema, table), {"schema": schema, "table": table, "columns": []})
            col: Dict[str, Any] = {"name": row["column"].strip()}
            if mtype:
                col["type"] = mtype
                if params:
                    col["params"] = params
            if domain:
                col["domain"] = domain
            entry["columns"].append(col)
    return parse_rules({"tables": list(raw_tables.values())}, path)
