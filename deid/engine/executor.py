"""Executes a plan: builds the value map, updates tables in batches or single statements, handles
FKs/triggers/unique indexes, checkpoints for resume, and records the audit trail."""

from __future__ import annotations

import datetime as _dt
import json
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .. import __version__
from ..advisor import resolve_workers
from ..audit import AuditTrail, new_run_id
from ..config import Rules, Settings
from ..database.connection import acquire_run_lock, server_info, with_retry
from ..database.schema import ColumnInfo, SchemaCatalog, enabled_triggers, fk_status, index_disabled
from ..database.sql import hash_expr, qualified, quote_ident
from ..masking import ALGORITHM_VERSION, BaseMasker, KeyRing, build_maskers, column_masker
from .parallel import MaskingPool
from .planner import ColumnPlan, Plan, PlanError, TablePlan, build_plan
from .sql import MAP_DDL, MAP_MASKED_MAX, chunk_bound_sql, distinct_values_sql, update_sql
from .validation import check_fits

log = logging.getLogger("deid.engine")

MAX_REPORTED_ERRORS = 10
PARALLEL_MIN_ROWS = 100000


class TableFailed(Exception):
    pass


class RunLocked(PlanError):
    """Another masking run holds the database's run lock."""


@dataclass
class ColumnStats:
    distinct_before: int = 0
    distinct_after: Optional[int] = None
    collisions: int = 0
    truncated: int = 0
    errors: List[str] = field(default_factory=list)

    def add_error(self, message: str) -> None:
        if len(self.errors) < MAX_REPORTED_ERRORS:
            self.errors.append(message)


def _truncate_limit(cp: ColumnPlan, masker: BaseMasker, targets: List[ColumnInfo]) -> int:
    """Free text with on_overflow: truncate is cut to the narrowest target column; 0 = never cut."""
    if cp.domain.type == "free_text" and masker.params.get("on_overflow") == "truncate":
        return min([c.max_chars for c in targets if c.max_chars and c.max_chars > 0] or [0])
    return 0


def _fit(masked: Optional[str], targets: List[ColumnInfo], truncate_to: int,
         st: ColumnStats) -> Tuple[Optional[str], Optional[str]]:
    """(value, None) when the masked value fits every target column, else (value, error)."""
    if truncate_to and masked is not None and len(masked) > truncate_to:
        masked = masked[:truncate_to]
        st.truncated += 1
    return masked, next((e for e in (check_fits(c, masked) for c in targets) if e), None)


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
        self.lock_conn = None
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
        for c in (self.read, self.work, self.audit_conn, self.lock_conn):  # closing lock_conn releases the lock
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
        conn = self._audit_factory().connect(autocommit=True)
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
        if not dry_run:
            self._acquire_lock(info)
        if db_audit:
            self.audit_conn = self._audit_factory().connect(autocommit=True)
        audit = AuditTrail(self.settings.audit, run_id, self.audit_conn if db_audit else None)
        audit.ensure_schema()
        state: Dict[str, Any] = {"run_id": run_id, "fks_disabled": [], "indexes_disabled": []}
        if resume_from:
            state.update(self._resume_state(resume_from))
        self._state = state

        audit.start_run("dry-run" if dry_run else "run", dict(
            info, tool_version=__version__, rules_file=str(self.rules.source_path or ""),
            rules_hash=self.rules.content_hash, key_fingerprint=self.keyring.fingerprint(),
            profile=self.rules.profile, policy=dict(self.rules.policy),
            algorithm_version=ALGORITHM_VERSION, resumed_from=resume_from, tables_planned=len(plan.tables),
            workers=self.workers, masking_mode=plan.mode,
        ))
        for w in plan.warnings:
            audit.event("WARN", w)
        if resume_from:
            audit.copy_progress(resume_from)
        progress = audit.table_progress(run_id)
        audit.save_state(state)

        self._open_work(audit, dry_run)
        completed, total_rows, failures = 0, 0, []
        try:
            if not dry_run:
                self._disable_fks(plan, state, audit)
            completed, total_rows, failures = self._process_tables(plan, run_id, dry_run, audit, progress,
                                                                       resume_from)
        finally:
            if not dry_run:
                failures.extend(self._finish_constraints(completed == len(plan.tables), state, audit, run_id))
            self._rollback_work()

        status = self._final_status(dry_run, failures, completed)
        audit.end_run(status, "; ".join(failures), completed, total_rows)
        return {"run_id": run_id, "status": status, "tables_completed": completed, "tables": len(plan.tables),
                "rows_updated": total_rows, "failures": failures, "audit_dir": str(audit.dir)}

    # ---- hooks: on-the-fly masking (copier.CopyEngine) writes to a target instead of the source
    def _audit_factory(self):
        """Connections to the database that is changed (and holds the audit trail and the run lock)."""
        return self.factory

    def _written_database(self, info: Dict[str, Any]) -> str:
        return info.get("database", "")

    @property
    def _ddl(self):
        """Connection that toggles constraints of the tables being written."""
        return self.work

    def _toggle_fks(self, plan: Plan) -> List[Any]:
        return plan.foreign_keys

    def _open_work(self, audit: AuditTrail, dry_run: bool) -> None:
        _close_quietly(self.work)   # from an earlier execute() (e.g. the dry run before the run)
        self.work = self.factory.connect(autocommit=False)

    def _rollback_work(self) -> None:
        for c in (self.work,):
            try:
                c.rollback()
            except Exception as exc:
                log.debug("Final rollback failed: %s", exc.__class__.__name__)

    def _acquire_lock(self, info: Dict[str, Any]) -> None:
        """One masking run per database at a time (scheduled and manual runs alike)."""
        self.lock_conn = self._audit_factory().connect(autocommit=True)
        db = self._written_database(info)
        if not acquire_run_lock(self.lock_conn, "pythondeid:%s" % db):
            raise RunLocked("Another masking run is in progress on database %s; try again when it has finished" % db)

    def _resume_state(self, resume_from: str) -> Dict[str, Any]:
        """Constraints left disabled by the run being resumed; refuses if the rules or key changed."""
        out_dir = self.settings.audit["output_dir"]
        prev = AuditTrail.load_state(out_dir, resume_from)
        prev_summary = _load_summary(out_dir, resume_from)
        if prev_summary.get("rules_hash") != self.rules.content_hash:
            raise PlanError("Rules changed since run %s; resume needs the identical rules file" % resume_from)
        if prev_summary.get("key_fingerprint") != self.keyring.fingerprint():
            raise PlanError("Secret key differs from run %s; resume needs the same DEID_SECRET_KEY" % resume_from)
        return {"fks_disabled": list(prev.get("fks_disabled", [])),
                "indexes_disabled": list(prev.get("indexes_disabled", [])), "resumed_from": resume_from}

    def _process_tables(self, plan: Plan, run_id: str, dry_run: bool, audit: AuditTrail,
                        progress: Dict[Any, Dict[str, Any]], resume_from: Optional[str]) -> Tuple[int, int, List[str]]:
        """Masks (or scans) each table in plan order; returns (tables completed, rows updated, failures)."""
        completed, total_rows, failures = 0, 0, []
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
        return completed, total_rows, failures

    def _finish_constraints(self, all_done: bool, state: Dict[str, Any], audit: AuditTrail, run_id: str) -> List[str]:
        """Re-enables FKs WITH CHECK once every table is done; otherwise leaves them for --resume."""
        problems: List[str] = []
        if all_done:
            problems = self._enable_fks(state, audit)
        elif state["fks_disabled"]:
            msg = ("Foreign keys left disabled because not all tables completed: %s. Fix the error and run "
                   "'python main.py run --resume %s'." % (", ".join(f["name"] for f in state["fks_disabled"]), run_id))
            log.warning(msg)
            audit.event("WARN", msg)
        audit.save_state(state)
        return problems

    def _final_status(self, dry_run: bool, failures: List[str], completed: int) -> str:
        if dry_run:
            return "DRY_RUN_OK" if not failures else "DRY_RUN_ISSUES"
        if not failures:
            return "SUCCEEDED"
        # FAILED only when nothing was committed; otherwise the re-run guard must treat the data as touched.
        return "PARTIAL" if (completed or self._data_changed) else "FAILED"

    # ------------------------------------------------------------------ constraints
    def _disable_fks(self, plan: Plan, state: Dict[str, Any], audit: AuditTrail) -> None:
        conn = self._ddl
        cur = conn.cursor()
        known = {(f["schema"].lower(), f["name"].lower()) for f in state["fks_disabled"]}
        for fk in self._toggle_fks(plan):
            if fk.is_disabled or (fk.schema.lower(), fk.name.lower()) in known:
                # Disabled before this run (left alone) or by the run being resumed (re-enabled at the end).
                continue
            cur.execute("ALTER TABLE %s NOCHECK CONSTRAINT %s" % (qualified(fk.schema, fk.table), quote_ident(fk.name)))
            conn.commit()
            state["fks_disabled"].append({"schema": fk.schema, "table": fk.table, "name": fk.name})
            audit.save_state(state)
            audit.event("INFO", "Disabled FK %s" % fk.name, fk.child_fqn)
            log.info("Disabled FK %s on %s", fk.name, fk.child_fqn)

    def _enable_fks(self, state: Dict[str, Any], audit: AuditTrail) -> List[str]:
        problems = []
        conn = self._ddl
        cur = conn.cursor()
        remaining = []
        for f in state["fks_disabled"]:
            target = qualified(f["schema"], f["table"])
            try:
                cur.execute("ALTER TABLE %s WITH CHECK CHECK CONSTRAINT %s" % (target, quote_ident(f["name"])))
                conn.commit()
                disabled, untrusted = fk_status(conn, f["schema"], f["name"])
                if disabled or untrusted:
                    raise RuntimeError("constraint is still disabled/untrusted")
                audit.event("INFO", "Re-enabled and validated FK %s (WITH CHECK)" % f["name"], target)
                log.info("Re-enabled and validated FK %s", f["name"])
            except Exception as exc:
                conn.rollback()
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
        """Mask every distinct value of each column and (when writing) load the results into #deid_map."""
        stats = {cp.ordinal: ColumnStats() for cp in tp.columns}
        ins = None
        if write:
            self.work.cursor().execute(MAP_DDL)
            ins = self._map_insert_cursor()
        parallel = self.workers > 1 and tp.info.row_count >= PARALLEL_MIN_ROWS
        for cp in tp.columns:
            if not cp.is_nullify:  # nullify needs no map: the UPDATE sets NULL directly
                self._map_column(tp, cp, stats[cp.ordinal], ins, parallel)
        if write:
            self.work.commit()
        return stats

    def _map_column(self, tp: TablePlan, cp: ColumnPlan, st: ColumnStats, ins, parallel: bool) -> None:
        masker = self._col_masker(tp, cp)
        check = bool(self.ex.get("collision_check", True) and masker.collision_check)
        seen = self._collisions.setdefault(cp.domain.name, {}) if check else None
        targets = cp.fit_targets
        truncate_to = _truncate_limit(cp, masker, targets)
        rcur = self.read.cursor()
        rcur.execute(distinct_values_sql(tp, cp))
        batches = self._fetch_batches(rcur, int(self.ex.get("fetch_size", 20000)))
        for _, results in self.pool.map(masker, cp.overrides, batches, check, parallel):
            batch = []
            for h, masked, err, digest in results:
                st.distinct_before += 1
                if err is None:
                    masked, err = _fit(masked, targets, truncate_to, st)
                if err:
                    st.add_error(err)
                    continue
                if seen is not None and masked is not None:
                    self._check_collision(cp, seen, masked, digest, st)
                batch.append((cp.ordinal, h, masked))
            if ins is not None and batch and not st.errors:
                ins.executemany("INSERT INTO #deid_map (col_ord, h, masked) VALUES (?, ?, ?)", batch)
        if st.truncated:
            log.info("%s.%s: %d free-text value(s) truncated to fit the column", tp.fqn, cp.name, st.truncated)
        log.debug("%s.%s: %d distinct values mapped", tp.fqn, cp.name, st.distinct_before)

    def _check_collision(self, cp: ColumnPlan, seen: Dict[str, bytes], masked: str, digest, st: ColumnStats) -> None:
        """Two different inputs must never share a masked value in a domain that claims uniqueness."""
        if cp.domain.name in self._collision_capped:
            return
        prior = seen.get(masked)
        if prior is None:
            cap = int(self.ex.get("collision_check_max_values", 5000000))
            if len(seen) >= cap:
                self._collision_capped.add(cp.domain.name)
                log.warning("Collision check for domain '%s' covered the first %d values (cap "
                            "execution.collision_check_max_values)", cp.domain.name, cap)
            else:
                seen[masked] = digest
        elif prior != digest:
            st.collisions += 1
            st.add_error("collision: two different values mask to the same output in domain "
                         "'%s' (increase token_length)" % cp.domain.name)

    def _map_insert_cursor(self):
        """Cursor for bulk inserts into #deid_map: fast_executemany with fixed parameter types (set once)."""
        cur = self.work.cursor()
        cur.fast_executemany = True
        try:
            import pyodbc
            cur.setinputsizes([(pyodbc.SQL_INTEGER, 0, 0), (pyodbc.SQL_VARBINARY, 32, 0),
                               (pyodbc.SQL_WVARCHAR, MAP_MASKED_MAX, 0)])
        except (ImportError, AttributeError):  # pragma: no cover - pyodbc missing / older version
            pass
        return cur

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


def _close_quietly(conn) -> None:
    if conn is None:
        return
    try:
        conn.rollback()
        conn.close()
    except Exception as exc:
        log.debug("Closing a connection failed: %s", exc.__class__.__name__)


def _utc():
    return _dt.datetime.now(_dt.timezone.utc).replace(tzinfo=None, microsecond=0)


def _load_summary(output_dir: str, run_id: str) -> Dict[str, Any]:
    p = Path(output_dir) / run_id / "summary.json"
    if not p.exists():
        raise PlanError("No audit summary found for run %s in %s" % (run_id, output_dir))
    with p.open(encoding="utf-8") as fh:
        return json.load(fh)
