"""Loading and validation of settings.yaml (environment) and deid_rules.yaml (what to mask)."""

from __future__ import annotations

import copy
import csv
import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    import yaml
except ImportError:  # PyYAML-ft (free-threading build, e.g. some ActiveState runtimes) installs as yaml_ft
    import yaml_ft as yaml

from .maskers import ALGORITHM_VERSION, MaskerError, get_masker_class


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
    "security": {"secret_key_env": "DEID_SECRET_KEY", "min_key_length": 32, "expected_key_fingerprint": ""},
    "execution": {
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
    "audit": {"write_to_db": True, "schema": "deid_audit", "output_dir": "audit"},
    "logging": {"level": "INFO", "dir": "logs"},
}

_SECTIONS = ("database", "security", "execution", "batching", "audit", "logging")

_AUTH_MODES = ("windows", "sql", "azure_ad_interactive", "azure_ad_password")


@dataclass
class Settings:
    database: Dict[str, Any]
    security: Dict[str, Any]
    execution: Dict[str, Any]
    batching: Dict[str, Any]
    audit: Dict[str, Any]
    logging: Dict[str, Any]
    source_path: Optional[Path] = None

    def to_dict(self) -> Dict[str, Any]:
        return {k: copy.deepcopy(getattr(self, k)) for k in _SECTIONS}


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
    for k in ("fetch_size", "max_retries", "collision_check_max_values"):
        if not isinstance(ex[k], int) or ex[k] < (0 if k == "max_retries" else 1):
            raise ConfigError("execution.%s must be a positive integer" % k)
    for k in ("batch_size", "workers"):
        if ex[k] != "auto" and (not isinstance(ex[k], int) or ex[k] < 1):
            raise ConfigError("execution.%s must be 'auto' or a positive integer" % k)
    if ex["type_mismatch"] not in ("error", "warn"):
        raise ConfigError("execution.type_mismatch must be 'error' or 'warn'")
    b = merged["batching"]
    for k in ("target_batch_mb", "min_batch_size", "max_batch_size"):
        if not isinstance(b[k], int) or b[k] < 1:
            raise ConfigError("batching.%s must be a positive integer" % k)
    if b["min_batch_size"] > b["max_batch_size"]:
        raise ConfigError("batching.min_batch_size must be <= max_batch_size")
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
    #: data type you expect the live column to have, e.g. "varchar(11)"; checked by validate
    expected_input_type: str = ""
    #: data type the masked values must fit, e.g. "char(11)" (default: the column's own type)
    output_type: str = ""
    #: format-only masker params for this column (e.g. ssn output_format); identity is unchanged
    overrides: Dict[str, Any] = field(default_factory=dict)
    #: column in the same table identifying the person/entity (date_shift shift_by: entity)
    entity_column: str = ""

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {"name": self.name, "domain": self.domain}
        for k in ("expected_input_type", "output_type", "entity_column"):
            if getattr(self, k):
                d[k] = getattr(self, k)
        d.update(self.overrides)
        return d


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
    algorithm_version: int = ALGORITHM_VERSION

    def to_dict(self) -> Dict[str, Any]:
        return {
            "algorithm_version": self.algorithm_version,
            "domains": {
                d.name: ({"type": d.type, "params": d.params} if d.params else {"type": d.type})
                for d in self.domains.values()
            },
            "tables": [
                dict(
                    {"schema": t.schema, "table": t.table},
                    **({"key_columns": t.key_columns} if t.key_columns else {}),
                    columns=[c.to_dict() for c in t.columns],
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
    unknown = set(raw) - {"domains", "tables", "algorithm_version"}
    if unknown:
        raise ConfigError("Unknown top-level key(s) in %s: %s" % (source, sorted(unknown)))
    version = raw.get("algorithm_version", ALGORITHM_VERSION)
    if version != ALGORITHM_VERSION:
        raise ConfigError(
            "%s pins algorithm_version %s but this tool implements version %s. Every server must run the same "
            "algorithm version or masked values will differ." % (source, version, ALGORITHM_VERSION))
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
            extra = set(c) - _COLUMN_KEYS
            dom = domains[dname]
            fmt_allowed = get_masker_class(dom.type).format_params
            bad = extra - set(fmt_allowed)
            if bad:
                raise ConfigError("%s: unknown key(s) %s for column '%s'. Column-level keys: %s; format overrides "
                                  "for %s: %s" % (cw, sorted(bad), c["name"], sorted(_COLUMN_KEYS), dom.type,
                                                  sorted(fmt_allowed) or "none"))
            overrides = {k: c[k] for k in extra}
            if overrides:
                try:
                    get_masker_class(dom.type).validate_params(dict(dom.params, **overrides))
                except MaskerError as exc:
                    raise ConfigError("%s: %s" % (cw, exc))
            entity = str(c.get("entity_column") or "")
            needs_entity = get_masker_class(dom.type).entity_required(get_masker_class(dom.type).validate_params(dom.params))
            if needs_entity and not entity:
                raise ConfigError("%s: domain '%s' uses shift_by: entity, so column '%s' needs entity_column "
                                  "(the person id column in this table)" % (cw, dname, c["name"]))
            if entity and not needs_entity:
                raise ConfigError("%s: entity_column is only valid for date_shift domains with shift_by: entity" % cw)
            cols.append(ColumnRule(str(c["name"]), dname, str(c.get("expected_input_type") or ""),
                                   str(c.get("output_type") or ""), overrides, entity))
        if not cols:
            raise ConfigError("%s: table %s.%s has no columns" % (where, schema, table))
        tables.append(TableRule(schema, table, cols, [str(k) for k in (t.get("key_columns") or [])]))

    for d in domains.values():
        for ref in get_masker_class(d.type).referenced_domains(get_masker_class(d.type).validate_params(d.params)):
            if ref not in domains:
                raise ConfigError("%s: domain '%s' masks free-text hits with domain '%s', which is not defined"
                                  % (source, d.name, ref))
    rules = Rules(domains=domains, tables=tables)
    rules.content_hash = rules.compute_hash()
    return rules


_COLUMN_KEYS = {"name", "domain", "type", "params", "expected_input_type", "output_type", "entity_column"}


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
               "suggested_type", "mask_type", "domain", "params_json", "expected_input_type", "output_type",
               "entity_column"]


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
            for k in ("expected_input_type", "output_type", "entity_column"):
                if (row.get(k) or "").strip():
                    col[k] = row[k].strip()
            entry["columns"].append(col)
    return parse_rules({"tables": list(raw_tables.values())}, path)
