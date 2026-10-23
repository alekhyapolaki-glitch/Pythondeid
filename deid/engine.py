"""Plans and executes de-identification against SQL Server.

How an update works (per table)
-------------------------------
1. For every target column, read the DISTINCT original values (grouped by their
   SHA-256 hash, so case/trailing-space variants are never merged) on a
   separate read connection.
2. Mask each distinct value in Python (deterministic per domain), validate the
   result fits the column, check for collisions, and bulk-load
   ``(column ordinal, sha256(original), masked)`` into a session temp table
   ``#deid_map``.  Original values are never written anywhere.
3. A set-based ``UPDATE ... FROM table LEFT JOIN #deid_map`` rewrites the table:
   * strategy ``chunked`` - key ranges of a single-column, unmasked key, one
     transaction per chunk with an atomic checkpoint (resumable);
   * strategy ``single`` - one statement / one transaction, used when the key
     itself is masked, a masked column is unique, or no usable key exists
     (avoids transient duplicate-key errors and double masking).

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
import hashlib
import json
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from . import __version__
from .audit import AuditTrail, new_run_id
from .config import DomainRule, Rules, Settings
from .db import qualified, quote_ident, server_info, with_retry
from .maskers import BaseMasker, KeyRing, MaskerError, create_masker, get_masker_class, is_injective
from .schema import INT_RANGES, ColumnInfo, ForeignKey, SchemaCatalog, TableInfo, enabled_triggers, fk_status

log = logging.getLogger("deid.engine")

MAP_MASKED_MAX = 4000
MAX_REPORTED_ERRORS = 10


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
            lines.append("  %s  [~%d rows, strategy=%s, key=%s]" % (
                tp.fqn, tp.info.row_count, tp.strategy, ",".join(tp.key_columns) or "-"))
            for cp in tp.columns:
                lines.append("      - %-30s %-16s -> domain '%s' (%s)%s" % (
                    cp.name, cp.info.type_display(), cp.domain.name, cp.domain.type,
                    "  [auto-added via FK]" if cp.auto_added else ""))
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


def build_plan(catalog: SchemaCatalog, rules: Rules, execution: Dict[str, Any], chunking_available: bool) -> Plan:
    errors: List[str] = []
    warnings: List[str] = []
    targets: Dict[Tuple[str, str], Dict[str, Tuple[str, bool]]] = {}  # (s,t) -> col_lower -> (domain, auto)
    order: List[Tuple[str, str]] = []
    key_override: Dict[Tuple[str, str], List[str]] = {}

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
            targets[k][cr.name.lower()] = (cr.domain, False)

    # ---- referential integrity closure over foreign keys --------------------
    fks: Dict[Tuple[str, str], ForeignKey] = {}
    queue = [(k, c) for k in order for c in list(targets[k])]
    while queue:
        (s, t), c = queue.pop(0)
        domain, _ = targets[(s, t)][c]
        for fk, side, os_, ot, oc in catalog.fks_touching(s, t, c):
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
                targets[ok_key][oc.lower()] = (domain, True)
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
    for k in order:
        ti = catalog.get(*k)
        cols: List[ColumnPlan] = []
        for ordinal, (cname, (dname, auto)) in enumerate(targets[k].items(), start=1):
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
            domain_families.setdefault(dname, set()).add(ci.family)
            cols.append(ColumnPlan(ci, dom, ordinal, auto))

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
        uniq = [c.name for c in cols if ti.is_unique_column(c.name)]
        if uniq:
            reasons.append("masked column(s) %s are unique" % ", ".join(uniq))
        if reasons:
            tp.strategy = "single"
            tp.notes.append("single-statement update: " + "; ".join(reasons))
            limit = execution.get("allow_single_statement_rows", 50000000)
            if ti.row_count > limit:
                warnings.append("%s has ~%d rows and will be updated in ONE transaction (%s); ensure transaction log "
                                "space or add key_columns." % (ti.fqn, ti.row_count, "; ".join(reasons)))
        else:
            tp.strategy = "chunked"
        tables.append(tp)

    for dname, fams in domain_families.items():
        if len(fams) > 1:
            warnings.append("Domain '%s' is used on columns of different type families %s; values only stay "
                            "consistent where their text form is identical (e.g. '00123' vs 123 differ)."
                            % (dname, sorted(fams)))
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


def distinct_values_sql(tp: TablePlan, cp: ColumnPlan) -> str:
    return (
        "SELECT %s AS h, MIN(%s) AS v FROM %s AS t WHERE t.%s IS NOT NULL GROUP BY %s"
        % (hash_expr("t", cp.info), text_expr("t", cp.info), tp.sql_name, quote_ident(cp.name), hash_expr("t", cp.info))
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
                     % (a, a, cp.ordinal, a, hash_expr("t", cp.info)))
        conds.append("%s.h IS NOT NULL" % a)
    where = "(" + " OR ".join(conds) + ")"
    if ranged:
        qk = quote_ident(tp.key_columns[0])
        where += (" AND t.%s > ? AND t.%s <= ?" % (qk, qk)) if lower_bound else (" AND t.%s <= ?" % qk)
    return "UPDATE t SET %s FROM %s AS t %s WHERE %s" % (", ".join(sets), tp.sql_name, " ".join(joins), where)


def chunk_bound_sql(tp: TablePlan, lower_bound: bool) -> str:
    qk = quote_ident(tp.key_columns[0])
    return "SELECT MAX(x.k) FROM (SELECT TOP (?) t.%s AS k FROM %s AS t %s ORDER BY t.%s) AS x" % (
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
            return "masked value length %d exceeds column length %d" % (len(masked), mc)
    elif fam == "int":
        try:
            n = int(masked)
        except ValueError:
            return "masked value is not an integer"
        lo, hi = INT_RANGES[col.data_type.lower()]
        if not lo <= n <= hi:
            return "masked value is out of %s range" % col.data_type
    elif fam == "decimal":
        try:
            d = decimal.Decimal(masked)
        except decimal.InvalidOperation:
            return "masked value is not numeric"
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
    errors: List[str] = field(default_factory=list)


class Engine:
    def __init__(self, settings: Settings, rules: Rules, keyring: KeyRing, conn_factory):
        self.settings = settings
        self.rules = rules
        self.keyring = keyring
        self.factory = conn_factory
        self.ex = settings.execution
        self.maskers: Dict[str, BaseMasker] = {
            d.name: create_masker(d.type, d.name, keyring, d.params) for d in rules.domains.values()
        }
        self._collisions: Dict[str, Dict[str, bytes]] = {}
        self.read = None
        self.work = None
        self.audit_conn = None

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
        for c in (self.read, self.work, self.audit_conn):
            try:
                if c is not None:
                    c.close()
            except Exception:  # noqa: BLE001
                pass

    def plan(self) -> Plan:
        catalog = SchemaCatalog.load(self.read)
        return build_plan(catalog, self.rules, self.ex, bool(self.settings.audit.get("write_to_db", True)))

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
        state: Dict[str, Any] = {"run_id": run_id, "fks_disabled": [], "triggers_disabled": {}}

        if resume_from:
            prev = AuditTrail.load_state(self.settings.audit["output_dir"], resume_from)
            prev_summary = _load_summary(self.settings.audit["output_dir"], resume_from)
            if prev_summary.get("rules_hash") != self.rules.content_hash:
                raise PlanError("Rules changed since run %s; resume needs the identical rules file" % resume_from)
            if prev_summary.get("key_fingerprint") != self.keyring.fingerprint():
                raise PlanError("Secret key differs from run %s; resume needs the same DEID_SECRET_KEY" % resume_from)
            state["fks_disabled"] = list(prev.get("fks_disabled", []))
            state["resumed_from"] = resume_from

        audit.start_run(mode, dict(
            info, tool_version=__version__, rules_file=str(self.rules.source_path or ""),
            rules_hash=self.rules.content_hash, key_fingerprint=self.keyring.fingerprint(),
            resumed_from=resume_from, tables_planned=len(plan.tables),
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
                except Exception as exc:  # noqa: BLE001 - recorded, then optionally stop
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
            except Exception:  # noqa: BLE001
                pass

        if dry_run:
            status = "DRY_RUN_OK" if not failures else "DRY_RUN_ISSUES"
        elif not failures:
            status = "SUCCEEDED"
        else:
            status = "PARTIAL" if completed else "FAILED"
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
            except Exception as exc:  # noqa: BLE001
                self.work.rollback()
                remaining.append(f)
                msg = "FK %s on %s failed validation after masking: %s" % (f["name"], target, exc)
                problems.append(msg)
                audit.event("ERROR", msg, target)
                log.error(msg)
        state["fks_disabled"] = remaining
        return problems

    # ------------------------------------------------------------------ table
    def _process_table(self, tp: TablePlan, run_id: str, dry_run: bool, audit: AuditTrail, prog: Dict[str, Any]) -> int:
        started = _utc()
        t0 = time.time()
        log.info("%s %s (%d columns, strategy=%s)", "Scanning" if dry_run else "Masking", tp.fqn, len(tp.columns), tp.strategy)
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
                except Exception as exc:  # noqa: BLE001
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
        cur.execute("SELECT %s FROM %s" % (", ".join(exprs), tp.sql_name))
        row = cur.fetchone()
        out = {0: int(row[0])}
        for cp, v in zip(tp.columns, row[1:]):
            out[cp.ordinal] = int(v)
        return out

    def _distinct_count(self, tp: TablePlan, cp: ColumnPlan) -> int:
        cur = self.read.cursor()
        cur.execute("SELECT COUNT_BIG(*) FROM (SELECT 1 AS x FROM %s AS t WHERE t.%s IS NOT NULL GROUP BY %s) AS z"
                    % (tp.sql_name, quote_ident(cp.name), hash_expr("t", cp.info)))
        return int(cur.fetchone()[0])

    def _build_map(self, tp: TablePlan, write: bool) -> Dict[int, ColumnStats]:
        stats = {cp.ordinal: ColumnStats() for cp in tp.columns}
        fetch = int(self.ex.get("fetch_size", 5000))
        ins = None
        if write:
            self.work.cursor().execute(MAP_DDL)
            ins = self.work.cursor()
            ins.fast_executemany = True
        for cp in tp.columns:
            if cp.is_nullify:
                continue
            masker = self.maskers[cp.domain.name]
            st = stats[cp.ordinal]
            check = self.ex.get("collision_check", True) and masker.collision_check
            seen = self._collisions.setdefault(cp.domain.name, {}) if check else None
            rcur = self.read.cursor()
            rcur.execute(distinct_values_sql(tp, cp))
            while True:
                rows = rcur.fetchmany(fetch)
                if not rows:
                    break
                batch = []
                for h, value in rows:
                    st.distinct_before += 1
                    try:
                        masked = masker.mask(value)
                    except MaskerError as exc:
                        if len(st.errors) < MAX_REPORTED_ERRORS:
                            st.errors.append(str(exc))
                        continue
                    err = check_fits(cp.info, masked)
                    if err:
                        if len(st.errors) < MAX_REPORTED_ERRORS:
                            st.errors.append(err)
                        continue
                    if seen is not None and masked is not None:
                        src = hashlib.sha256(masker.canonical(value).encode("utf-8")).digest()[:16]
                        prior = seen.setdefault(masked, src)
                        if prior != src:
                            st.collisions += 1
                            if len(st.errors) < MAX_REPORTED_ERRORS:
                                st.errors.append("collision: two different values mask to the same output in domain "
                                                 "'%s' (increase token_length)" % cp.domain.name)
                    batch.append((cp.ordinal, bytes(h), masked))
                if write and batch and not st.errors:
                    self._insert_map(ins, batch)
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
        except Exception:  # noqa: BLE001
            pass

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
            return n

        return self._retry(work, "update of %s" % tp.fqn)

    def _update_chunked(self, tp: TablePlan, run_id: str, audit: AuditTrail, prog: Dict[str, Any]) -> int:
        batch = int(self.ex.get("batch_size", 50000))
        key_is_int = tp.key_info.family == "int"
        last = prog.get("last_key")
        if last is not None:
            last = int(last) if key_is_int else last
            log.info("Resuming %s after key %s", tp.fqn, last)
        total = 0
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
                return upper, n

            upper, n = self._retry(chunk, "chunk of %s" % tp.fqn)
            if upper is None:
                break
            last = upper
            total += n
            log.info("  %s: %d rows updated so far (key <= %s)", tp.fqn, total, last)
        cur = self.work.cursor()
        cur.execute(audit.progress_upsert_sql(),
                    audit.progress_params(run_id, tp.info.schema, tp.info.name, "COMPLETED", last, 0))
        self.work.commit()
        return total

    def _record(self, audit, tp, stats, counts, status, rows, started, message) -> None:
        for cp in tp.columns:
            st = stats[cp.ordinal]
            audit.column_result({
                "schema_name": tp.info.schema, "table_name": tp.info.name, "column_name": cp.name,
                "domain": cp.domain.name, "mask_type": cp.domain.type, "strategy": tp.strategy, "status": status,
                "rows_total": counts.get(0), "rows_non_null_before": counts.get(cp.ordinal),
                "distinct_before": st.distinct_before if not cp.is_nullify else None,
                "rows_updated": rows, "distinct_after": st.distinct_after, "collisions": st.collisions,
                "message": message or ("; ".join(st.errors) if st.errors else ""),
                "started_at": started, "ended_at": _utc(),
            })


def _utc():
    return _dt.datetime.now(_dt.timezone.utc).replace(tzinfo=None).replace(microsecond=0)


def _load_summary(output_dir: str, run_id: str) -> Dict[str, Any]:
    p = Path(output_dir) / run_id / "summary.json"
    if not p.exists():
        raise PlanError("No audit summary found for run %s in %s" % (run_id, output_dir))
    with p.open(encoding="utf-8") as fh:
        return json.load(fh)
