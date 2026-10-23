"""Plans and executes de-identification against SQL Server.

How an update works (per table)
-------------------------------
1. For every target column, read the DISTINCT original values (grouped by their
   SHA-256 hash, so case/trailing-space variants are never merged) on a
   separate read connection.  For per-person date shifting the grouping key is
   (person id, date).
2. Mask each distinct value (deterministic per domain; optionally in parallel
   worker processes), validate the result fits the column and the configured
   ``output_type``, check for collisions, and bulk-load
   ``(column ordinal, sha256(original), masked)`` into a session temp table
   ``#deid_map``.  Original values are never written anywhere.
3. A set-based ``UPDATE ... FROM table LEFT JOIN #deid_map`` rewrites the table:
   * strategy ``chunked`` - key ranges of a single-column, unmasked key, one
     transaction per chunk with an atomic checkpoint (resumable).  The chunk
     size is sized from the table's average row size (``batch_size: auto``).
     Masked columns covered by nonclustered unique indexes are allowed: those
     indexes are disabled for the update and rebuilt (re-validated) afterwards.
   * strategy ``single`` - one statement / one transaction, used when the key
     itself is masked, a masked column is in the PK/clustered or an FK-referenced
     unique index, or no usable key exists.

Run-level safety
----------------
* Foreign keys that touch masked columns are switched to NOCHECK before the
  first table and re-validated ``WITH CHECK`` after the last one.
* Every FK column pair must be masked with the same domain (or is added
  automatically when ``auto_include_fk_columns`` is on); ON UPDATE CASCADE
  FKs on masked columns are rejected (they would double-mask).
* Enabled triggers on the table are disabled for the update and re-enabled.
* Re-running a completed rules set is blocked unless forced, because masking
  already-masked data would break consistency with other masked databases.
"""

from __future__ import annotations

import datetime as _dt
import decimal
import json
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from . import __version__
from .advisor import estimate_log_mb, recommend_batch_size, resolve_workers
from .audit import AuditTrail, new_run_id
from .config import ColumnRule, DomainRule, Rules, Settings
from .db import qualified, quote_ident, server_info, with_retry
from .maskers import ALGORITHM_VERSION, BaseMasker, KeyRing, build_maskers, column_masker, get_masker_class, is_injective
from .parallel import MaskingPool
from .schema import (INT_RANGES, ColumnInfo, ForeignKey, IndexInfo, SchemaCatalog, TableInfo, enabled_triggers,
                     fk_status, index_disabled, parse_type, same_type)

log = logging.getLogger("deid.engine")

MAP_MASKED_MAX = 4000
MAX_REPORTED_ERRORS = 10
PARALLEL_MIN_ROWS = 100000


class PlanError(Exception):
    pass


class TableFailed(Exception):
    pass


# =============================================================================
# Plan
# =============================================================================
@dataclass
class ColumnPlan:
    info: ColumnInfo
    domain: DomainRule
    ordinal: int
    auto_added: bool = False
    entity_info: Optional[ColumnInfo] = None
    output_info: Optional[ColumnInfo] = None
    overrides: Dict[str, Any] = field(default_factory=dict)
    expected_input_type: str = ""

    @property
    def name(self) -> str:
        return self.info.name

    @property
    def is_nullify(self) -> bool:
        return self.domain.type == "nullify"


@dataclass
class TablePlan:
    info: TableInfo
    columns: List[ColumnPlan]
    key_columns: List[str] = field(default_factory=list)
    strategy: str = "single"
    batch_size: int = 0
    disable_indexes: List[IndexInfo] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)

    @property
    def fqn(self) -> str:
        return self.info.fqn

    @property
    def sql_name(self) -> str:
        return qualified(self.info.schema, self.info.name)

    @property
    def key_info(self) -> Optional[ColumnInfo]:
        return self.info.column(self.key_columns[0]) if self.key_columns else None


@dataclass
class Plan:
    tables: List[TablePlan]
    foreign_keys: List[ForeignKey]
    warnings: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors

    def describe(self) -> str:
        lines = ["De-identification plan: %d table(s), %d column(s)" % (
            len(self.tables), sum(len(t.columns) for t in self.tables))]
        for tp in self.tables:
            size_mb = tp.info.data_bytes / 1048576.0
            if tp.strategy == "chunked":
                chunks = -(-tp.info.row_count // max(tp.batch_size, 1)) if tp.info.row_count else 0
                how = "chunked, %d rows/batch (~%d batches)" % (tp.batch_size, chunks)
            else:
                how = "single transaction, ~%d MB log" % estimate_log_mb(tp.info)
            lines.append("  %s  [~%d rows, %.1f MB, %s, key=%s]" % (
                tp.fqn, tp.info.row_count, size_mb, how, ",".join(tp.key_columns) or "-"))
            for cp in tp.columns:
                extra = []
                if cp.auto_added:
                    extra.append("auto-added via FK")
                if cp.entity_info is not None:
                    extra.append("per-person shift by %s" % cp.entity_info.name)
                if cp.output_info is not None:
                    extra.append("output_type %s" % cp.output_info.type_display())
                for k in ("method", "mode"):
                    if k in cp.domain.params:
                        extra.append("%s=%s" % (k, cp.domain.params[k]))
                if cp.overrides:
                    extra.append(", ".join("%s=%s" % kv for kv in cp.overrides.items()))
                lines.append("      - %-30s %-16s -> domain '%s' (%s)%s" % (
                    cp.name, cp.info.type_display(), cp.domain.name, cp.domain.type,
                    ("  [%s]" % "; ".join(extra)) if extra else ""))
            for ix in tp.disable_indexes:
                lines.append("      note: unique index %s disabled during update, rebuilt afterwards" % ix.name)
            for n in tp.notes:
                lines.append("      note: %s" % n)
        if self.foreign_keys:
            lines.append("  Foreign keys toggled during the run:")
            for fk in self.foreign_keys:
                lines.append("      - %s on %s -> %s%s" % (
                    fk.name, fk.child_fqn, fk.parent_fqn, " (currently disabled)" if fk.is_disabled else ""))
        for w in self.warnings:
            lines.append("WARNING: " + w)
        for e in self.errors:
            lines.append("ERROR:   " + e)
        return "\n".join(lines)


def build_plan(catalog: SchemaCatalog, rules: Rules, execution: Dict[str, Any], chunking_available: bool,
               batching: Optional[Dict[str, Any]] = None) -> Plan:
    errors: List[str] = []
    warnings: List[str] = []
    # (s,t) -> col_lower -> (domain, auto_added, ColumnRule or None)
    targets: Dict[Tuple[str, str], Dict[str, Tuple[str, bool, Optional[ColumnRule]]]] = {}
    order: List[Tuple[str, str]] = []
    key_override: Dict[Tuple[str, str], List[str]] = {}
    batching = batching or {}

    for tr in rules.tables:
        ti = catalog.get(tr.schema, tr.table)
        if ti is None:
            errors.append("Table %s does not exist (or is not visible to this login)" % tr.fqn)
            continue
        k = (ti.schema.lower(), ti.name.lower())
        order.append(k)
        targets[k] = {}
        key_override[k] = tr.key_columns
        for cr in tr.columns:
            if ti.column(cr.name) is None:
                errors.append("Column %s.%s does not exist" % (tr.fqn, cr.name))
                continue
            targets[k][cr.name.lower()] = (cr.domain, False, cr)

    # ---- referential integrity closure over foreign keys --------------------
    fks: Dict[Tuple[str, str], ForeignKey] = {}
    queue = [(k, c) for k in order for c in list(targets[k])]
    while queue:
        (s, t), c = queue.pop(0)
        domain = targets[(s, t)][c][0]
        for fk, _side, os_, ot, oc in catalog.fks_touching(s, t, c):
            fks[(fk.schema.lower(), fk.name.lower())] = fk
            if fk.update_action == 1:
                errors.append(
                    "FK %s (%s -> %s) is ON UPDATE CASCADE on masked column %s; cascading would double-mask the "
                    "child. Change the FK to NO ACTION for the masking run." % (fk.name, fk.child_fqn, fk.parent_fqn, c))
            ok_key = (os_.lower(), ot.lower())
            other = targets.get(ok_key, {}).get(oc.lower())
            if other is not None:
                if other[0] != domain:
                    errors.append(
                        "FK %s links %s.%s.%s (domain '%s') and %s.%s.%s (domain '%s'); both sides must use the same "
                        "domain or the relationship breaks." % (fk.name, s, t, c, domain, os_, ot, oc, other[0]))
                continue
            if execution.get("auto_include_fk_columns", True) and catalog.get(os_, ot) is not None:
                if ok_key not in targets:
                    targets[ok_key] = {}
                    order.append(ok_key)
                    key_override[ok_key] = []
                targets[ok_key][oc.lower()] = (domain, True, None)
                queue.append((ok_key, oc.lower()))
                warnings.append("Auto-added %s.%s.%s (domain '%s') because FK %s references masked column %s.%s.%s"
                                % (os_, ot, oc, domain, fk.name, s, t, c))
            else:
                errors.append(
                    "FK %s links masked column %s.%s.%s to %s.%s.%s which is not masked; add it with domain '%s' "
                    "(or enable execution.auto_include_fk_columns)." % (fk.name, s, t, c, os_, ot, oc, domain))

    # ---- per table checks and strategy ------------------------------------
    tables: List[TablePlan] = []
    domain_families: Dict[str, set] = {}
    mismatch = execution.get("type_mismatch", "error")
    for k in order:
        ti = catalog.get(*k)
        cols: List[ColumnPlan] = []
        for ordinal, (cname, (dname, auto, rule)) in enumerate(targets[k].items(), start=1):
            ci = ti.column(cname)
            dom = rules.domains.get(dname)
            if dom is None:
                errors.append("Domain '%s' used by %s.%s is not defined" % (dname, ti.fqn, ci.name))
                continue
            cls = get_masker_class(dom.type)
            where = "%s.%s (%s)" % (ti.fqn, ci.name, ci.type_display())
            if ci.is_computed:
                errors.append("%s is a computed column and cannot be updated; mask its source columns" % where)
            if ci.is_identity:
                errors.append("%s is an IDENTITY column and cannot be updated" % where)
            if ci.family not in cls.families:
                errors.append("%s: mask type '%s' supports %s columns only" % (where, dom.type, "/".join(cls.families)))
            if dom.type == "nullify" and not ci.is_nullable:
                errors.append("%s is NOT NULL; it cannot be nullified" % where)
            if ti.is_unique_column(ci.name) and not is_injective(dom.type, dom.params):
                errors.append("%s is part of a primary key/unique index but '%s' is not collision-free; use an "
                              "injective type (fpe, account_number, ssn, email, hash, ...)" % (where, dom.type))
            cp = ColumnPlan(ci, dom, ordinal, auto)
            if rule is not None:
                cp.overrides = dict(rule.overrides)
                cp.expected_input_type = rule.expected_input_type
                if rule.expected_input_type:
                    try:
                        if not same_type(rule.expected_input_type, ci):
                            msg = ("%s: expected_input_type is %s but the live column is %s"
                                   % (where, rule.expected_input_type, ci.type_display()))
                            (errors if mismatch == "error" else warnings).append(msg)
                    except ValueError as exc:
                        errors.append("%s: %s" % (where, exc))
                if rule.output_type:
                    try:
                        cp.output_info = parse_type(rule.output_type, ci.name, ci.is_nullable)
                    except ValueError as exc:
                        errors.append("%s: %s" % (where, exc))
                    else:
                        if cp.output_info.family != ci.family and cls is not get_masker_class("nullify"):
                            warnings.append("%s: output_type %s is a different type family than the column; values "
                                            "are validated against both" % (where, rule.output_type))
                if rule.entity_column:
                    ei = ti.column(rule.entity_column)
                    if ei is None:
                        errors.append("%s: entity_column %s does not exist in %s" % (where, rule.entity_column, ti.fqn))
                    elif ei.family == "other":
                        errors.append("%s: entity_column %s has unsupported type %s" % (where, ei.name, ei.data_type))
                    else:
                        cp.entity_info = ei
            elif cls.entity_required(cls.validate_params(dom.params)):
                errors.append("%s was auto-added with per-person date domain '%s' but has no entity_column; add it "
                              "to the rules explicitly" % (where, dname))
            domain_families.setdefault(dname, set()).add(ci.family)
            cols.append(cp)

        tp = TablePlan(ti, cols)
        masked = {c.name.lower() for c in cols}
        key = key_override.get(k) or ti.primary_key
        if not key:
            for us in ti.unique_sets:
                if all(ti.column(c) and not ti.column(c).is_nullable for c in us) and not masked & {c.lower() for c in us}:
                    key = us
                    break
        for kc in key:
            if ti.column(kc) is None:
                errors.append("%s: key column %s does not exist" % (ti.fqn, kc))
        tp.key_columns = [ti.column(kc).name for kc in key if ti.column(kc) is not None]

        reasons = []
        if not chunking_available:
            reasons.append("audit.write_to_db is off (checkpoints need it)")
        if len(tp.key_columns) != 1:
            reasons.append("no single-column key" if not tp.key_columns else "composite key")
        elif tp.key_columns[0].lower() in masked:
            reasons.append("key column is masked")
        elif tp.key_info.family not in ("int", "string"):
            reasons.append("key type %s not supported for chunking" % tp.key_info.data_type)
        blocking, disable = [], []
        for c in cols:
            for ix in ti.unique_indexes_on(c.name):
                if ix.can_disable and execution.get("disable_unique_indexes", True):
                    if ix not in disable:
                        disable.append(ix)
                else:
                    blocking.append("%s (%s)" % (c.name, ix.name))
        if blocking:
            reasons.append("masked column(s) %s are in a PK/clustered/FK-referenced unique index" % ", ".join(blocking))
        if reasons:
            tp.strategy = "single"
            tp.notes.append("single-statement update: " + "; ".join(reasons))
            limit = execution.get("allow_single_statement_rows", 50000000)
            if ti.row_count > limit:
                warnings.append("%s has ~%d rows and will be updated in ONE transaction (~%d MB log) because %s. "
                                "Make sure the log can hold it, or provide an unmasked key_columns."
                                % (ti.fqn, ti.row_count, estimate_log_mb(ti), "; ".join(reasons)))
        else:
            tp.strategy = "chunked"
            tp.disable_indexes = disable
            bs = execution.get("batch_size", "auto")
            tp.batch_size = recommend_batch_size(ti, batching) if bs == "auto" else int(bs)
        tables.append(tp)

    for dname, fams in domain_families.items():
        dom = rules.domains.get(dname)
        normalized = dom is not None and (dom.params.get("normalize") == "digits" or dom.type == "ssn")
        if len(fams) > 1 and not normalized:
            warnings.append("Domain '%s' is used on columns of different type families %s; values only stay "
                            "consistent where their text form is identical (e.g. '00123' vs 123 differ). "
                            "Use params {normalize: digits, pad_to: N} (see 'recommend')." % (dname, sorted(fams)))
    return Plan(tables, list(fks.values()), warnings, errors)


# =============================================================================
# SQL builders
# =============================================================================
def text_expr(alias: str, col: ColumnInfo) -> str:
    """Canonical NVARCHAR text form of a column, identical in SELECT and UPDATE joins."""
    ref = "%s.%s" % (alias, quote_ident(col.name))
    t = col.data_type.lower()
    if t in ("datetime", "smalldatetime"):
        return "CONVERT(NVARCHAR(MAX), %s, 126)" % ref
    if t in ("money", "smallmoney"):
        return "CONVERT(NVARCHAR(MAX), %s, 2)" % ref
    return "CAST(%s AS NVARCHAR(MAX))" % ref


def hash_expr(alias: str, col: ColumnInfo) -> str:
    return "HASHBYTES('SHA2_256', %s)" % text_expr(alias, col)


def key_expr(alias: str, cp: ColumnPlan) -> str:
    """Map key: hash of the value, or of (entity, value) for per-person maskers."""
    if cp.entity_info is None:
        return hash_expr(alias, cp.info)
    return "HASHBYTES('SHA2_256', CONCAT(ISNULL(N'1' + %s, N'0'), NCHAR(31), %s))" % (
        text_expr(alias, cp.entity_info), text_expr(alias, cp.info))


def distinct_values_sql(tp: TablePlan, cp: ColumnPlan) -> str:
    entity = (", MIN(%s) AS e" % text_expr("t", cp.entity_info)) if cp.entity_info is not None else ""
    return (
        "SELECT %s AS h, MIN(%s) AS v%s FROM %s AS t WHERE t.%s IS NOT NULL GROUP BY %s"  # nosec B608
        % (key_expr("t", cp), text_expr("t", cp.info), entity, tp.sql_name, quote_ident(cp.name), key_expr("t", cp))
    )


def update_sql(tp: TablePlan, ranged: bool, lower_bound: bool) -> str:
    sets, joins, conds = [], [], []
    for cp in tp.columns:
        qc = quote_ident(cp.name)
        if cp.is_nullify:
            sets.append("%s = NULL" % qc)
            conds.append("t.%s IS NOT NULL" % qc)
            continue
        a = "m%d" % cp.ordinal
        current = "t.%s" % qc
        if cp.info.data_type.lower() in ("text", "ntext"):
            current = "CAST(t.%s AS NVARCHAR(MAX))" % qc
        sets.append("%s = CASE WHEN %s.h IS NULL THEN %s ELSE %s.masked END" % (qc, a, current, a))
        joins.append("LEFT JOIN #deid_map AS %s ON %s.col_ord = %d AND %s.h = %s"
                     % (a, a, cp.ordinal, a, key_expr("t", cp)))
        conds.append("%s.h IS NOT NULL" % a)
    where = "(" + " OR ".join(conds) + ")"
    if ranged:
        qk = quote_ident(tp.key_columns[0])
        where += (" AND t.%s > ? AND t.%s <= ?" % (qk, qk)) if lower_bound else (" AND t.%s <= ?" % qk)
    return "UPDATE t SET %s FROM %s AS t %s WHERE %s" % (", ".join(sets), tp.sql_name, " ".join(joins), where)  # nosec B608


def chunk_bound_sql(tp: TablePlan, lower_bound: bool) -> str:
    qk = quote_ident(tp.key_columns[0])
    return "SELECT MAX(x.k) FROM (SELECT TOP (?) t.%s AS k FROM %s AS t %s ORDER BY t.%s) AS x" % (  # nosec B608
        qk, tp.sql_name, ("WHERE t.%s > ?" % qk) if lower_bound else "", qk)


MAP_DDL = (
    "IF OBJECT_ID('tempdb..#deid_map') IS NOT NULL DROP TABLE #deid_map; "
    "CREATE TABLE #deid_map (col_ord INT NOT NULL, h VARBINARY(32) NOT NULL, masked NVARCHAR(%d) NULL, "
    "PRIMARY KEY (col_ord, h));" % MAP_MASKED_MAX
)


# =============================================================================
# Validation of masked values against the target column
# =============================================================================
def check_fits(col: ColumnInfo, masked: Optional[str]) -> Optional[str]:
    if masked is None:
        return None if col.is_nullable else "masked value is NULL but column is NOT NULL"
    if len(masked) > MAP_MASKED_MAX:
        return "masked value longer than %d characters is not supported" % MAP_MASKED_MAX
    fam = col.family
    if fam == "string":
        mc = col.max_chars
        if mc and mc > 0 and len(masked) > mc:
            return "masked value length %d exceeds %s" % (len(masked), col.type_display())
    elif fam == "int":
        try:
            n = int(masked)
        except ValueError:
            return "masked value is not an integer (%s)" % col.type_display()
        lo, hi = INT_RANGES[col.data_type.lower()]
        if not lo <= n <= hi:
            return "masked value is out of %s range" % col.data_type
    elif fam == "decimal":
        try:
            d = decimal.Decimal(masked)
        except decimal.InvalidOperation:
            return "masked value is not numeric (%s)" % col.type_display()
        if col.data_type.lower() in ("decimal", "numeric"):
            int_digits = len(str(abs(int(d)))) if int(d) != 0 else 0
            if int_digits > col.precision - col.scale:
                return "masked value exceeds %s(%d,%d)" % (col.data_type, col.precision, col.scale)
    elif fam == "date":
        try:
            year = int(masked.strip()[:4])
        except ValueError:
            return "masked value is not a date"
        t = col.data_type.lower()
        if (t == "datetime" and year < 1753) or (t == "smalldatetime" and not 1900 <= year <= 2079):
            return "masked date is outside the %s range" % t
    return None


# =============================================================================
# Execution
# =============================================================================
@dataclass
class ColumnStats:
    distinct_before: int = 0
    non_null_before: int = 0
    distinct_after: Optional[int] = None
    collisions: int = 0
    truncated: int = 0
    errors: List[str] = field(default_factory=list)


class Engine:
    def __init__(self, settings: Settings, rules: Rules, keyring: KeyRing, conn_factory):
        self.settings = settings
        self.rules = rules
        self.keyring = keyring
        self.factory = conn_factory
        self.ex = settings.execution
        pinned = (settings.security.get("expected_key_fingerprint") or "").strip()
        if pinned and pinned != keyring.fingerprint():
            raise PlanError(
                "DEID_SECRET_KEY does not match security.expected_key_fingerprint (%s, got %s). Every server must use "
                "the same key or masked values will differ between databases." % (pinned, keyring.fingerprint()))
        self.maskers: Dict[str, BaseMasker] = build_maskers(rules.domains.values(), keyring)
        self._col_maskers: Dict[Tuple[str, str], BaseMasker] = {}
        self._collisions: Dict[str, Dict[str, bytes]] = {}
        self._collision_capped: set = set()
        self.workers = resolve_workers(self.ex.get("workers", "auto"))
        self.pool = MaskingPool(self.workers, rules.domains.values(), keyring)
        self.read = None
        self.work = None
        self.audit_conn = None
        self._state: Dict[str, Any] = {}
        self._data_changed = False  # any masked data committed in this run (=> never report FAILED)

    # ------------------------------------------------------------------ connections
    def connect(self) -> Dict[str, Any]:
        self.read = self.factory.connect(autocommit=True)
        info = server_info(self.read)
        log.info("Connected to %s / %s as %s (SQL Server %s, %s)", info["server"], info["database"],
                 info["login"], info["version"], info["edition"])
        major = int(str(info["version"]).split(".")[0])
        if major < 13:
            raise PlanError("SQL Server 2016 (13.x) or later is required (HASHBYTES on NVARCHAR(MAX))")
        return info

    def close(self) -> None:
        self.pool.close()
        for c in (self.read, self.work, self.audit_conn):
            try:
                if c is not None:
                    c.close()
            except Exception as exc:
                log.debug("Closing a connection failed: %s", exc.__class__.__name__)

    def plan(self) -> Plan:
        catalog = SchemaCatalog.load(self.read)
        return build_plan(catalog, self.rules, self.ex, bool(self.settings.audit.get("write_to_db", True)),
                          self.settings.batching)

    def previous_runs(self) -> List[Dict[str, Any]]:
        if not self.settings.audit.get("write_to_db", True):
            return []
        conn = self.factory.connect(autocommit=True)
        try:
            cur = conn.cursor()
            s = self.settings.audit["schema"]
            cur.execute("SELECT OBJECT_ID(?, 'U')", ["%s.run" % s])
            if cur.fetchone()[0] is None:
                return []
            return AuditTrail(self.settings.audit, "lookup", conn).previous_runs()
        finally:
            conn.close()

    def _col_masker(self, tp: TablePlan, cp: ColumnPlan) -> BaseMasker:
        key = (tp.fqn, cp.name)
        m = self._col_maskers.get(key)
        if m is None:
            m = column_masker(self.maskers[cp.domain.name], self.keyring, cp.overrides)
            self._col_maskers[key] = m
        return m

    # ------------------------------------------------------------------ run
    def execute(self, plan: Plan, dry_run: bool, info: Dict[str, Any], resume_from: Optional[str] = None) -> Dict[str, Any]:
        if not plan.ok:
            raise PlanError("Plan has errors; run 'validate' and fix them first")
        run_id = new_run_id()
        db_audit = bool(self.settings.audit.get("write_to_db", True)) and not dry_run
        if db_audit:
            self.audit_conn = self.factory.connect(autocommit=True)
        audit = AuditTrail(self.settings.audit, run_id, self.audit_conn if db_audit else None)
        audit.ensure_schema()
        mode = "dry-run" if dry_run else "run"
        state: Dict[str, Any] = {"run_id": run_id, "fks_disabled": [], "indexes_disabled": []}
        self._state = state

        if resume_from:
            prev = AuditTrail.load_state(self.settings.audit["output_dir"], resume_from)
            prev_summary = _load_summary(self.settings.audit["output_dir"], resume_from)
            if prev_summary.get("rules_hash") != self.rules.content_hash:
                raise PlanError("Rules changed since run %s; resume needs the identical rules file" % resume_from)
            if prev_summary.get("key_fingerprint") != self.keyring.fingerprint():
                raise PlanError("Secret key differs from run %s; resume needs the same DEID_SECRET_KEY" % resume_from)
            state["fks_disabled"] = list(prev.get("fks_disabled", []))
            state["indexes_disabled"] = list(prev.get("indexes_disabled", []))
            state["resumed_from"] = resume_from

        audit.start_run(mode, dict(
            info, tool_version=__version__, rules_file=str(self.rules.source_path or ""),
            rules_hash=self.rules.content_hash, key_fingerprint=self.keyring.fingerprint(),
            algorithm_version=ALGORITHM_VERSION, resumed_from=resume_from, tables_planned=len(plan.tables),
            workers=self.workers,
        ))
        for w in plan.warnings:
            audit.event("WARN", w)
        if resume_from:
            audit.copy_progress(resume_from)
        progress = audit.table_progress(run_id)
        audit.save_state(state)

        self.work = self.factory.connect(autocommit=False)
        completed = 0
        total_rows = 0
        failures: List[str] = []
        try:
            if not dry_run:
                self._disable_fks(plan, state, audit)
            for tp in plan.tables:
                prog = progress.get((tp.info.schema.lower(), tp.info.name.lower()), {})
                if prog.get("status") == "COMPLETED":
                    audit.event("INFO", "Skipped (completed in run %s)" % resume_from, tp.fqn)
                    log.info("Skipping %s (already completed)", tp.fqn)
                    completed += 1
                    continue
                try:
                    total_rows += self._process_table(tp, run_id, dry_run, audit, prog)
                    completed += 1
                except Exception as exc:
                    failures.append("%s: %s" % (tp.fqn, exc))
                    log.error("Table %s failed: %s", tp.fqn, exc)
                    audit.event("ERROR", str(exc), tp.fqn)
                    if self.ex.get("stop_on_error", True):
                        break
        finally:
            if not dry_run:
                if completed == len(plan.tables):
                    failures.extend(self._enable_fks(state, audit))
                elif state["fks_disabled"]:
                    msg = ("Foreign keys left disabled because not all tables completed: %s. Fix the error and run "
                           "'python main.py run --resume %s'." % (", ".join(f["name"] for f in state["fks_disabled"]), run_id))
                    log.warning(msg)
                    audit.event("WARN", msg)
                audit.save_state(state)
            try:
                self.work.rollback()
            except Exception as exc:
                log.debug("Final rollback failed: %s", exc.__class__.__name__)

        if dry_run:
            status = "DRY_RUN_OK" if not failures else "DRY_RUN_ISSUES"
        elif not failures:
            status = "SUCCEEDED"
        else:
            # FAILED only when nothing was committed; otherwise the re-run guard must treat the data as touched.
            status = "PARTIAL" if (completed or self._data_changed) else "FAILED"
        message = "; ".join(failures)
        audit.end_run(status, message, completed, total_rows)
        return {"run_id": run_id, "status": status, "tables_completed": completed, "tables": len(plan.tables),
                "rows_updated": total_rows, "failures": failures, "audit_dir": str(audit.dir)}

    # ------------------------------------------------------------------ constraints
    def _disable_fks(self, plan: Plan, state: Dict[str, Any], audit: AuditTrail) -> None:
        cur = self.work.cursor()
        known = {(f["schema"].lower(), f["name"].lower()) for f in state["fks_disabled"]}
        for fk in plan.foreign_keys:
            if fk.is_disabled or (fk.schema.lower(), fk.name.lower()) in known:
                # Disabled before this run (left alone) or by the run being resumed (re-enabled at the end).
                continue
            cur.execute("ALTER TABLE %s NOCHECK CONSTRAINT %s" % (qualified(fk.schema, fk.table), quote_ident(fk.name)))
            self.work.commit()
            state["fks_disabled"].append({"schema": fk.schema, "table": fk.table, "name": fk.name})
            audit.save_state(state)
            audit.event("INFO", "Disabled FK %s" % fk.name, fk.child_fqn)
            log.info("Disabled FK %s on %s", fk.name, fk.child_fqn)

    def _enable_fks(self, state: Dict[str, Any], audit: AuditTrail) -> List[str]:
        problems = []
        cur = self.work.cursor()
        remaining = []
        for f in state["fks_disabled"]:
            target = qualified(f["schema"], f["table"])
            try:
                cur.execute("ALTER TABLE %s WITH CHECK CHECK CONSTRAINT %s" % (target, quote_ident(f["name"])))
                self.work.commit()
                disabled, untrusted = fk_status(self.work, f["schema"], f["name"])
                if disabled or untrusted:
                    raise RuntimeError("constraint is still disabled/untrusted")
                audit.event("INFO", "Re-enabled and validated FK %s (WITH CHECK)" % f["name"], target)
                log.info("Re-enabled and validated FK %s", f["name"])
            except Exception as exc:
                self.work.rollback()
                remaining.append(f)
                msg = "FK %s on %s failed validation after masking: %s" % (f["name"], target, exc)
                problems.append(msg)
                audit.event("ERROR", msg, target)
                log.error(msg)
        state["fks_disabled"] = remaining
        return problems

    def _disable_unique_indexes(self, tp: TablePlan, audit: AuditTrail) -> None:
        mine = {(i["schema"], i["table"], i["name"]) for i in self._state["indexes_disabled"]}
        for ix in tp.disable_indexes:
            ident = (tp.info.schema, tp.info.name, ix.name)
            if index_disabled(self.work, *ident):
                continue  # disabled by the run being resumed (rebuilt below) or by the user (left alone)
            self.work.cursor().execute("ALTER INDEX %s ON %s DISABLE" % (quote_ident(ix.name), tp.sql_name))
            self.work.commit()
            if ident not in mine:
                self._state["indexes_disabled"].append({"schema": ident[0], "table": ident[1], "name": ident[2]})
            audit.save_state(self._state)
            audit.event("INFO", "Disabled unique index %s for batched update" % ix.name, tp.fqn)

    def _rebuild_unique_indexes(self, tp: TablePlan, audit: AuditTrail) -> None:
        for rec in list(self._state["indexes_disabled"]):
            if (rec["schema"].lower(), rec["table"].lower()) != (tp.info.schema.lower(), tp.info.name.lower()):
                continue
            log.info("Rebuilding unique index %s on %s", rec["name"], tp.fqn)
            self.work.cursor().execute("ALTER INDEX %s ON %s REBUILD" % (quote_ident(rec["name"]), tp.sql_name))
            self.work.commit()
            self._state["indexes_disabled"].remove(rec)
            audit.save_state(self._state)
            audit.event("INFO", "Rebuilt and re-validated unique index %s" % rec["name"], tp.fqn)

    # ------------------------------------------------------------------ table
    def _process_table(self, tp: TablePlan, run_id: str, dry_run: bool, audit: AuditTrail, prog: Dict[str, Any]) -> int:
        started = _utc()
        t0 = time.time()
        log.info("%s %s (%d columns, ~%d rows, strategy=%s%s)", "Scanning" if dry_run else "Masking", tp.fqn,
                 len(tp.columns), tp.info.row_count, tp.strategy,
                 ", batch=%d" % tp.batch_size if tp.strategy == "chunked" else "")
        counts = self._counts(tp)
        stats = self._build_map(tp, write=not dry_run)
        for cp in tp.columns:
            stats[cp.ordinal].non_null_before = counts[cp.ordinal]

        problems = ["%s: %s" % (cp.name, e) for cp in tp.columns for e in stats[cp.ordinal].errors]
        if problems:
            self._record(audit, tp, stats, counts, "FAILED" if not dry_run else "INVALID", 0, started,
                         "; ".join(problems[:MAX_REPORTED_ERRORS]))
            raise TableFailed("%d masked value(s) failed validation, nothing was updated: %s"
                              % (len(problems), "; ".join(problems[:3])))
        if dry_run:
            self._record(audit, tp, stats, counts, "DRY_RUN", 0, started, "")
            return 0

        triggers = enabled_triggers(self.work, tp.info.schema, tp.info.name) if self.ex.get("disable_triggers", True) else []
        cur = self.work.cursor()
        rows = 0
        try:
            for trg in triggers:
                cur.execute("DISABLE TRIGGER %s ON %s" % (qualified(tp.info.schema, trg), tp.sql_name))
            self.work.commit()
            if triggers:
                audit.event("INFO", "Disabled triggers: %s" % ", ".join(triggers), tp.fqn)
            if tp.strategy == "chunked":
                self._disable_unique_indexes(tp, audit)
                rows = self._update_chunked(tp, run_id, audit, prog)
            else:
                rows = self._update_single(tp, run_id, audit)
        except Exception as exc:
            self.work.rollback()
            self._record(audit, tp, stats, counts, "FAILED", rows, started, str(exc))
            raise
        finally:
            for trg in triggers:
                try:
                    self.work.cursor().execute("ENABLE TRIGGER %s ON %s" % (qualified(tp.info.schema, trg), tp.sql_name))
                    self.work.commit()
                except Exception as exc:
                    audit.event("ERROR", "Could not re-enable trigger %s: %s" % (trg, exc), tp.fqn)
            if triggers:
                audit.event("INFO", "Re-enabled triggers: %s" % ", ".join(triggers), tp.fqn)
            self._drop_map()

        for cp in tp.columns:
            if not cp.is_nullify:
                stats[cp.ordinal].distinct_after = self._distinct_count(tp, cp)
        self._record(audit, tp, stats, counts, "COMPLETED", rows, started, "")
        log.info("Masked %s: %d rows updated in %.1fs", tp.fqn, rows, time.time() - t0)
        return rows

    def _counts(self, tp: TablePlan) -> Dict[int, int]:
        cur = self.read.cursor()
        exprs = ["COUNT_BIG(*)"] + ["COUNT_BIG(%s)" % quote_ident(cp.name) for cp in tp.columns]
        cur.execute("SELECT %s FROM %s" % (", ".join(exprs), tp.sql_name))  # nosec B608
        row = cur.fetchone()
        out = {0: int(row[0])}
        for cp, v in zip(tp.columns, row[1:]):
            out[cp.ordinal] = int(v)
        return out

    def _distinct_count(self, tp: TablePlan, cp: ColumnPlan) -> int:
        cur = self.read.cursor()
        cur.execute("SELECT COUNT_BIG(*) FROM (SELECT 1 AS x FROM %s AS t WHERE t.%s IS NOT NULL GROUP BY %s) AS z"  # nosec B608
                    % (tp.sql_name, quote_ident(cp.name), hash_expr("t", cp.info)))
        return int(cur.fetchone()[0])

    def _fetch_batches(self, cur, size: int):
        while True:
            rows = cur.fetchmany(size)
            if not rows:
                return
            yield [tuple(r) for r in rows]

    def _build_map(self, tp: TablePlan, write: bool) -> Dict[int, ColumnStats]:
        stats = {cp.ordinal: ColumnStats() for cp in tp.columns}
        fetch = int(self.ex.get("fetch_size", 20000))
        cap = int(self.ex.get("collision_check_max_values", 5000000))
        parallel = self.workers > 1 and tp.info.row_count >= PARALLEL_MIN_ROWS
        ins = None
        if write:
            self.work.cursor().execute(MAP_DDL)
            ins = self.work.cursor()
            ins.fast_executemany = True
        for cp in tp.columns:
            if cp.is_nullify:
                continue
            masker = self._col_masker(tp, cp)
            st = stats[cp.ordinal]
            check = bool(self.ex.get("collision_check", True) and masker.collision_check)
            seen = self._collisions.setdefault(cp.domain.name, {}) if check else None
            truncate = cp.domain.type == "free_text" and masker.params.get("on_overflow") == "truncate"
            targets = [cp.info] + ([cp.output_info] if cp.output_info is not None else [])
            rcur = self.read.cursor()
            rcur.execute(distinct_values_sql(tp, cp))
            for _, results in self.pool.map(masker, cp.overrides, self._fetch_batches(rcur, fetch), check, parallel):
                batch = []
                for h, masked, err, digest in results:
                    st.distinct_before += 1
                    if err is None and truncate and masked is not None:
                        limit = min([c.max_chars for c in targets if c.max_chars and c.max_chars > 0] or [0])
                        if limit and len(masked) > limit:
                            masked = masked[:limit]
                            st.truncated += 1
                    if err is None:
                        err = next((e for e in (check_fits(c, masked) for c in targets) if e), None)
                    if err:
                        if len(st.errors) < MAX_REPORTED_ERRORS:
                            st.errors.append(err)
                        continue
                    if seen is not None and masked is not None and cp.domain.name not in self._collision_capped:
                        prior = seen.get(masked)
                        if prior is None:
                            if len(seen) >= cap:
                                self._collision_capped.add(cp.domain.name)
                                log.warning("Collision check for domain '%s' covered the first %d values (cap "
                                            "execution.collision_check_max_values)", cp.domain.name, cap)
                            else:
                                seen[masked] = digest
                        elif prior != digest:
                            st.collisions += 1
                            if len(st.errors) < MAX_REPORTED_ERRORS:
                                st.errors.append("collision: two different values mask to the same output in domain "
                                                 "'%s' (increase token_length)" % cp.domain.name)
                    batch.append((cp.ordinal, h, masked))
                if write and batch and not st.errors:
                    self._insert_map(ins, batch)
            if st.truncated:
                log.info("%s.%s: %d free-text value(s) truncated to fit the column", tp.fqn, cp.name, st.truncated)
            log.debug("%s.%s: %d distinct values mapped", tp.fqn, cp.name, st.distinct_before)
        if write:
            self.work.commit()
        return stats

    @staticmethod
    def _insert_map(cur, batch) -> None:
        try:
            import pyodbc
            cur.setinputsizes([(pyodbc.SQL_INTEGER, 0, 0), (pyodbc.SQL_VARBINARY, 32, 0),
                               (pyodbc.SQL_WVARCHAR, MAP_MASKED_MAX, 0)])
        except (ImportError, AttributeError):  # pragma: no cover
            pass
        cur.executemany("INSERT INTO #deid_map (col_ord, h, masked) VALUES (?, ?, ?)", batch)

    def _drop_map(self) -> None:
        try:
            self.work.cursor().execute("IF OBJECT_ID('tempdb..#deid_map') IS NOT NULL DROP TABLE #deid_map")
            self.work.commit()
        except Exception as exc:
            log.warning("Could not drop #deid_map: %s", exc.__class__.__name__)

    def _retry(self, fn, what):
        return with_retry(fn, self.work, int(self.ex.get("max_retries", 3)),
                          float(self.ex.get("retry_backoff_seconds", 2)), what)

    def _update_single(self, tp: TablePlan, run_id: str, audit: AuditTrail) -> int:
        sql = update_sql(tp, ranged=False, lower_bound=False)

        def work() -> int:
            cur = self.work.cursor()
            cur.execute(sql)
            n = max(cur.rowcount, 0)
            if audit.db_enabled:
                cur.execute(audit.progress_upsert_sql(),
                            audit.progress_params(run_id, tp.info.schema, tp.info.name, "COMPLETED", None, n))
            self.work.commit()
            self._data_changed = True
            return n

        return self._retry(work, "update of %s" % tp.fqn)

    def _update_chunked(self, tp: TablePlan, run_id: str, audit: AuditTrail, prog: Dict[str, Any]) -> int:
        batch = tp.batch_size
        key_is_int = tp.key_info.family == "int"
        last = prog.get("last_key")
        if last is not None:
            last = int(last) if key_is_int else last
            log.info("Resuming %s after key %s", tp.fqn, last)
        total = 0
        t0 = time.time()
        while True:
            def chunk(lower=last):
                cur = self.work.cursor()
                if lower is None:
                    cur.execute(chunk_bound_sql(tp, False), [batch])
                else:
                    cur.execute(chunk_bound_sql(tp, True), [batch, lower])
                upper = cur.fetchone()[0]
                if upper is None:
                    return None, 0
                if lower is None:
                    cur.execute(update_sql(tp, True, False), [upper])
                else:
                    cur.execute(update_sql(tp, True, True), [lower, upper])
                n = max(cur.rowcount, 0)
                cur.execute(audit.progress_upsert_sql(),
                            audit.progress_params(run_id, tp.info.schema, tp.info.name, "IN_PROGRESS", upper, n))
                self.work.commit()
                self._data_changed = True
                return upper, n

            upper, n = self._retry(chunk, "chunk of %s" % tp.fqn)
            if upper is None:
                break
            last = upper
            total += n
            rate = total / max(time.time() - t0, 0.001)
            log.info("  %s: %d rows updated so far (key <= %s, %.0f rows/s)", tp.fqn, total, last, rate)
        self._rebuild_unique_indexes(tp, audit)
        cur = self.work.cursor()
        cur.execute(audit.progress_upsert_sql(),
                    audit.progress_params(run_id, tp.info.schema, tp.info.name, "COMPLETED", last, 0))
        self.work.commit()
        return total

    def _record(self, audit, tp, stats, counts, status, rows, started, message) -> None:
        for cp in tp.columns:
            st = stats[cp.ordinal]
            note = message or ("; ".join(st.errors) if st.errors else "")
            if st.truncated:
                note = (note + "; " if note else "") + "%d value(s) truncated" % st.truncated
            audit.column_result({
                "schema_name": tp.info.schema, "table_name": tp.info.name, "column_name": cp.name,
                "domain": cp.domain.name, "mask_type": cp.domain.type, "strategy": tp.strategy,
                "batch_size": tp.batch_size if tp.strategy == "chunked" else None, "status": status,
                "rows_total": counts.get(0), "rows_non_null_before": counts.get(cp.ordinal),
                "distinct_before": st.distinct_before if not cp.is_nullify else None,
                "rows_updated": rows, "distinct_after": st.distinct_after, "collisions": st.collisions,
                "message": note, "started_at": started, "ended_at": _utc(),
            })


def _utc():
    return _dt.datetime.now(_dt.timezone.utc).replace(tzinfo=None, microsecond=0)


def _load_summary(output_dir: str, run_id: str) -> Dict[str, Any]:
    p = Path(output_dir) / run_id / "summary.json"
    if not p.exists():
        raise PlanError("No audit summary found for run %s in %s" % (run_id, output_dir))
    with p.open(encoding="utf-8") as fh:
        return json.load(fh)
