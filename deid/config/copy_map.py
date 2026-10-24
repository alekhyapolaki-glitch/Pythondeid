"""copy_map.yaml: where on-the-fly masking writes (target connection, tables, column mapping).

The tables to copy are the tables in deid_rules.yaml (each masked column with its domain); this file
only says where they go and, when the target differs, which columns map to which.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from .base import ConfigError, _read_yaml
from .rules import Rules

MODES = ("in_place", "on_the_fly")
ON_EXISTING_ROWS = ("truncate", "error")
TRANSFERS = ("auto", "set_based", "stream")

_TOP_KEYS = {"target_connection", "on_existing_rows", "transfer", "disable_nonclustered_indexes", "tables"}
_TABLE_KEYS = {"source", "target", "columns", "column_map"}


@dataclass
class TableMapping:
    source_schema: str
    source_table: str
    target_schema: str
    target_table: str
    #: "all" = every copyable source column, or the source columns to copy
    columns: Union[str, List[str]] = "all"
    #: source column (lower-case) -> target column, only where the names differ
    column_map: Dict[str, str] = field(default_factory=dict)

    @property
    def source_fqn(self) -> str:
        return "%s.%s" % (self.source_schema, self.source_table)

    @property
    def target_fqn(self) -> str:
        return "%s.%s" % (self.target_schema, self.target_table)

    def target_column(self, source_column: str) -> str:
        return self.column_map.get(source_column.lower(), source_column)


@dataclass
class CopyMap:
    target_connection: str = ""
    on_existing_rows: str = "truncate"
    transfer: str = "auto"
    disable_nonclustered_indexes: bool = True
    tables: Dict[str, TableMapping] = field(default_factory=dict)   # source fqn (lower) -> mapping
    source_path: Optional[Path] = None
    content_hash: str = ""

    def mapping(self, schema: str, table: str) -> TableMapping:
        """The configured mapping, or the default: same schema, table and column names."""
        m = self.tables.get(("%s.%s" % (schema, table)).lower())
        return m if m is not None else TableMapping(schema, table, schema, table)


def _split_name(value: Any, where: str) -> List[str]:
    parts = str(value or "").split(".")
    if len(parts) != 2 or not all(p.strip() for p in parts):
        raise ConfigError("%s must be schema.table, got %r" % (where, value))
    return [p.strip() for p in parts]


def parse_copy_map(raw: Dict[str, Any], rules: Rules, source: str = "<copy_map>") -> CopyMap:
    unknown = set(raw) - _TOP_KEYS
    if unknown:
        raise ConfigError("%s: unknown key(s) %s (allowed: %s)" % (source, sorted(unknown), sorted(_TOP_KEYS)))
    cm = CopyMap(
        target_connection=str(raw.get("target_connection") or ""),
        on_existing_rows=str(raw.get("on_existing_rows", "truncate")),
        transfer=str(raw.get("transfer", "auto")),
        disable_nonclustered_indexes=raw.get("disable_nonclustered_indexes", True),
    )
    if cm.on_existing_rows not in ON_EXISTING_ROWS:
        raise ConfigError("%s: on_existing_rows must be one of %s" % (source, ", ".join(ON_EXISTING_ROWS)))
    if cm.transfer not in TRANSFERS:
        raise ConfigError("%s: transfer must be one of %s" % (source, ", ".join(TRANSFERS)))
    if not isinstance(cm.disable_nonclustered_indexes, bool):
        raise ConfigError("%s: disable_nonclustered_indexes must be true or false" % source)
    in_rules = {t.fqn.lower() for t in rules.tables}
    targets: Dict[str, str] = {}
    for i, entry in enumerate(raw.get("tables") or []):
        m = _parse_table(entry, "%s tables[%d]" % (source, i))
        key = m.source_fqn.lower()
        if key not in in_rules:
            raise ConfigError("%s tables[%d]: %s is not in the rules file; only tables in deid_rules.yaml are "
                              "copied (add it there with a domain for each masked column)" % (source, i, m.source_fqn))
        if key in cm.tables:
            raise ConfigError("%s: %s is listed twice" % (source, m.source_fqn))
        if m.target_fqn.lower() in targets:
            raise ConfigError("%s: %s and %s both write to %s" % (source, targets[m.target_fqn.lower()],
                                                                m.source_fqn, m.target_fqn))
        targets[m.target_fqn.lower()] = m.source_fqn
        cm.tables[key] = m
    blob = json.dumps(raw, sort_keys=True, default=str).encode("utf-8")
    cm.content_hash = hashlib.sha256(blob).hexdigest()[:16]
    return cm


def _parse_table(entry: Any, where: str) -> TableMapping:
    if not isinstance(entry, dict):
        raise ConfigError("%s must be a mapping" % where)
    unknown = set(entry) - _TABLE_KEYS
    if unknown:
        raise ConfigError("%s: unknown key(s) %s (allowed: %s)" % (where, sorted(unknown), sorted(_TABLE_KEYS)))
    ss, st = _split_name(entry.get("source"), where + ".source")
    ts, tt = _split_name(entry["target"], where + ".target") if entry.get("target") else (ss, st)
    return TableMapping(ss, st, ts, tt, _parse_columns(entry.get("columns", "all"), where),
                        _parse_column_map(entry.get("column_map") or {}, where))


def _parse_columns(cols: Any, where: str) -> Union[str, List[str]]:
    if cols == "all":
        return cols
    if not isinstance(cols, list) or not cols or not all(isinstance(c, str) and c.strip() for c in cols):
        raise ConfigError("%s.columns must be 'all' or a list of source column names" % where)
    if len({c.lower() for c in cols}) != len(cols):
        raise ConfigError("%s.columns lists a column twice" % where)
    return cols


def _parse_column_map(cmap: Any, where: str) -> Dict[str, str]:
    if not isinstance(cmap, dict) or not all(isinstance(k, str) and isinstance(v, str) and v.strip()
                                             for k, v in cmap.items()):
        raise ConfigError("%s.column_map must map source column names to target column names" % where)
    lowered = {k.lower(): v.strip() for k, v in cmap.items()}
    if len({v.lower() for v in lowered.values()}) != len(lowered):
        raise ConfigError("%s.column_map maps two source columns to the same target column" % where)
    return lowered


def load_copy_map(path: str, rules: Rules) -> CopyMap:
    """copy_map.yaml; when the file does not exist every table keeps its name in the target."""
    p = Path(path)
    if not p.exists():
        cm = CopyMap()
        cm.source_path = p
        return cm
    cm = parse_copy_map(_read_yaml(p) or {}, rules, str(p))
    cm.source_path = p
    return cm
