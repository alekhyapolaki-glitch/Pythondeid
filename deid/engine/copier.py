"""On-the-fly masking: read the source, mask, write the target.  The source database is never changed.

Per table:  mask map (source tempdb, same parallel masking and checks as in place)
            -> empty the target table (TRUNCATE, or batched DELETE when a foreign key references it)
            -> disable target triggers and nonclustered indexes
            -> load in key-range chunks, each committed together with its resume checkpoint
            -> row-count check (source vs target), rebuild indexes, re-enable triggers
Target foreign keys are disabled for the load and re-enabled WITH CHECK at the end, which proves the
copied data is referentially intact.

Transfer:
  set_based  same SQL Server instance (other database, or other table in the same database): one
             INSERT ... SELECT per chunk inside SQL Server; rows never leave the server.
  stream     different servers: the source session returns rows that are already masked; a reader
             thread fetches the next batch while the target connection writes the current one.
In both, a value missing from the mask map fails the statement (copy_sql) instead of being copied.
"""

from __future__ import annotations

import logging
import queue
import threading
import time
from typing import Any, Dict, Iterator, List, Optional

from ..audit import AuditTrail
from ..config import CopyMap
from ..database.connection import server_info, with_retry
from ..database.schema import SchemaCatalog, enabled_triggers, index_disabled, nonclustered_indexes
from ..database.sql import hash_expr, qualified, quote_ident
from .copy_plan import UDT_TYPES, build_copy_plan, set_transfer, travels_as_text
from .copy_sql import (
    DATE_TEXT_LEN,
    copy_insert_sql,
    copy_select_sql,
    identity_insert_sql,
    stream_insert_sql,
)
from .executor import MAX_REPORTED_ERRORS, Engine, TableFailed, _close_quietly, _utc
from .planner import Plan, PlanError, TablePlan, build_plan
from .sql import chunk_bound_sql

log = logging.getLogger("deid.engine")

#: memory budget for one streamed INSERT batch (pyodbc fast_executemany parameter arrays)
STREAM_BATCH_BYTES = 32 * 1024 * 1024


class CopyEngine(Engine):
    def __init__(self, settings, rules, keyring, conn_factory, target_factory, copy_map: CopyMap,
                 target_connection: str):
        super().__init__(settings, rules, keyring, conn_factory)
        self.target_factory = target_factory
        self.copy_map = copy_map
        self.target_connection = target_connection
        self.tread = None    # target, autocommit (catalog, checks)
        self.target = None   # target, transactional (loads, DDL)
        self.same_instance = False
        self._info: Dict[str, Any] = {}
        self._plan_transfer = "stream"
        self._audit_db: Optional[str] = None   # set-based: audit database for three-part checkpoint names

    # ------------------------------------------------------------------ connections and plan
    def connect(self) -> Dict[str, Any]:
        info = super().connect()
        self.tread = self.target_factory.connect(autocommit=True)
        t = server_info(self.tread)
        self.same_instance = str(t["instance"]).lower() == str(info["instance"]).lower()
        info["target"] = {"server": t["server"], "database": t["database"], "login": t["login"],
                          "instance": t["instance"], "connection": self.target_connection}
        log.info("Target %s / %s as %s (%s)", t["server"], t["database"], t["login"],
                 "same instance as the source" if self.same_instance else "different server")
        self._info = info
        return info

    def close(self) -> None:
        super().close()
        for c in (self.tread, self.target):
            try:
                if c is not None:
                    c.close()
            except Exception as exc:
                log.debug("Closing a target connection failed: %s", exc.__class__.__name__)

    def plan(self) -> Plan:
        plan = build_plan(SchemaCatalog.load(self.read), self.rules, self.ex,
                          bool(self.settings.audit.get("write_to_db", True)), self.settings.batching, mode="on_the_fly")
        t = self._info["target"]
        build_copy_plan(plan, self.copy_map, SchemaCatalog.load(self.tread), same_instance=self.same_instance,
                        source_database=self._info["database"], target_server=t["server"],
                        target_database=t["database"], target_connection=self.target_connection)
        if plan.copy.transfer == "set_based":
            missing = self._cross_database_gaps(plan)
            if missing and self.copy_map.transfer == "auto":
                plan.warnings.append("Streaming instead of set-based: the source login cannot write the target (%s)"
                                     % "; ".join(missing[:3]))
                set_transfer(plan, "stream")
            elif missing:
                plan.errors.extend("transfer set_based: %s" % m for m in missing)
        return plan

    def _cross_database_gaps(self, plan: Plan) -> List[str]:
        """Set-based writes the target from the source session: that login needs access and INSERT."""
        cur = self.read.cursor()
        db = plan.copy.target_database
        cur.execute("SELECT HAS_DBACCESS(?)", [db])
        if not cur.fetchone()[0]:
            return ["no access to database %s" % db]
        gaps = []
        for tp in plan.tables:
            if tp.target is None:
                continue
            name = tp.target.full_name
            for perm in ("INSERT",) + (("ALTER",) if tp.target.identity_insert else ()):
                cur.execute("SELECT HAS_PERMS_BY_NAME(?, 'OBJECT', ?)", [name, perm])
                if not cur.fetchone()[0]:
                    gaps.append("%s on %s" % (perm, name))
        return gaps

    # ------------------------------------------------------------------ engine hooks
    def _audit_factory(self):
        return self.target_factory

    def _written_database(self, info: Dict[str, Any]) -> str:
        return info["target"]["database"]

    @property
    def _ddl(self):
        return self.target

    def _toggle_fks(self, plan: Plan) -> List[Any]:
        return plan.copy.foreign_keys

    def _open_work(self, audit: AuditTrail, dry_run: bool) -> None:
        super()._open_work(audit, dry_run)
        _close_quietly(self.target)
        self.target = self.target_factory.connect(autocommit=False)
        self._audit_db = None
        if audit.db_enabled and not dry_run and self._plan_transfer == "set_based":
            # checkpoints are written from the source session, in the same transaction as the rows
            self._audit_db = self._info["target"]["database"]
            cur = self.read.cursor()
            name = audit.t("table_progress", self._audit_db)
            for perm in ("INSERT", "UPDATE"):
                cur.execute("SELECT HAS_PERMS_BY_NAME(?, 'OBJECT', ?)", [name, perm])
                if not cur.fetchone()[0]:
                    raise PlanError("transfer set_based: the source login needs %s on %s for resume checkpoints "
                                    "(grant it, or use transfer: stream)" % (perm, name))

    def _rollback_work(self) -> None:
        for c in (self.work, self.target):
            try:
                if c is not None:
                    c.rollback()
            except Exception as exc:
                log.debug("Final rollback failed: %s", exc.__class__.__name__)

    def _finish_constraints(self, all_done: bool, state: Dict[str, Any], audit: AuditTrail, run_id: str) -> List[str]:
        """After a complete load the FKs are validated WITH CHECK.  After an incomplete one they are switched
        back on without validating the partial data (untrusted), so a fresh re-run sees and handles them."""
        if all_done or not state["fks_disabled"]:
            return super()._finish_constraints(all_done, state, audit, run_id)
        for f in list(state["fks_disabled"]):
            try:
                self.target.cursor().execute("ALTER TABLE %s CHECK CONSTRAINT %s"
                                             % (qualified(f["schema"], f["table"]), quote_ident(f["name"])))
                self.target.commit()
                state["fks_disabled"].remove(f)
            except Exception as exc:
                self.target.rollback()
                audit.event("ERROR", "Could not re-enable FK %s: %s" % (f["name"], exc), f["table"])
        msg = ("The copy did not complete, so the target is partly loaded and its foreign keys are not validated. "
               "Fix the cause, then run again (reloads the target) or resume with --resume %s." % run_id)
        log.warning(msg)
        audit.event("WARN", msg)
        audit.save_state(state)
        return []

    def execute(self, plan: Plan, dry_run: bool, info: Dict[str, Any], resume_from: Optional[str] = None):
        self._plan_transfer = plan.copy.transfer if plan.copy is not None else "stream"
        return super().execute(plan, dry_run, info, resume_from)

    # ------------------------------------------------------------------ table
    def _process_table(self, tp: TablePlan, run_id: str, dry_run: bool, audit: AuditTrail, prog: Dict[str, Any]) -> int:
        started, t0 = _utc(), time.time()
        tgt = tp.target
        log.info("%s %s -> %s (%d masked columns, ~%d rows, %s%s)", "Scanning" if dry_run else "Copying", tp.fqn,
                 tgt.info.fqn, len(tp.columns), tp.info.row_count, tp.strategy,
                 ", batch=%d" % tp.batch_size if tp.strategy == "chunked" else "")
        counts = self._counts(tp)
        stats = self._build_map(tp, write=not dry_run)
        problems = ["%s: %s" % (cp.name, e) for cp in tp.columns for e in stats[cp.ordinal].errors]
        if problems:
            self._record(audit, tp, stats, counts, "FAILED" if not dry_run else "INVALID", 0, started,
                         "; ".join(problems[:MAX_REPORTED_ERRORS]))
            raise TableFailed("%d masked value(s) failed validation, nothing was written: %s"
                              % (len(problems), "; ".join(problems[:3])))
        if dry_run:
            self._record(audit, tp, stats, counts, "DRY_RUN", 0, started, "")
            return 0

        triggers = (enabled_triggers(self.target, tgt.info.schema, tgt.info.name)
                    if self.ex.get("disable_triggers", True) else [])
        rows = 0
        try:
            if prog.get("status") != "IN_PROGRESS":   # a resumed table keeps the chunks already loaded
                self._empty_target(tp, audit)
            self._set_triggers(tp, triggers, "DISABLE", audit)
            self._disable_target_indexes(tp, audit)
            rows = self._load(tp, run_id, audit, prog)
            self._check_row_count(tp, counts[0])
            self._rebuild_target_indexes(tp, audit)
        except Exception as exc:
            self._rollback_work()
            self._record(audit, tp, stats, counts, "FAILED", rows, started, str(exc))
            try:  # never leave the target with disabled indexes; a re-run or --resume reloads the data
                self._rebuild_target_indexes(tp, audit)
            except Exception as rb_exc:
                audit.event("ERROR", "Index rebuild after the failure did not complete: %s" % rb_exc, tgt.info.fqn)
            raise
        finally:
            self._set_triggers(tp, triggers, "ENABLE", audit)
            self._drop_map()
        for cp in tp.columns:
            if not cp.is_nullify:
                stats[cp.ordinal].distinct_after = self._target_distinct(tp, cp)
        self._record(audit, tp, stats, counts, "COMPLETED", rows, started, "")
        log.info("Copied %s -> %s: %d rows in %.1fs", tp.fqn, tgt.info.fqn, rows, time.time() - t0)
        return rows

    def _empty_target(self, tp: TablePlan, audit: AuditTrail) -> None:
        tgt = tp.target
        cur = self.target.cursor()
        cur.execute("SELECT COUNT_BIG(*) FROM %s" % tgt.sql_name)  # nosec B608
        existing = int(cur.fetchone()[0])
        self.target.commit()
        if not existing:
            return
        if self.copy_map.on_existing_rows == "error":
            raise TableFailed("target %s has %d row(s) and on_existing_rows is 'error'" % (tgt.info.fqn, existing))
        if not tgt.referenced_by_fk:
            cur.execute("TRUNCATE TABLE %s" % tgt.sql_name)
            self.target.commit()
        else:  # TRUNCATE is not allowed on a referenced table (even with the FK disabled)
            batch = max(tp.batch_size, 10000)
            while True:
                cur.execute("DELETE TOP (?) FROM %s" % tgt.sql_name, [batch])  # nosec B608
                n = cur.rowcount
                self.target.commit()
                if n < batch:
                    break
        audit.event("INFO", "Emptied target (%d rows, %s)" % (existing, "DELETE" if tgt.referenced_by_fk
                                                             else "TRUNCATE"), tgt.info.fqn)
        self._data_changed = True

    def _set_triggers(self, tp: TablePlan, triggers: List[str], action: str, audit: AuditTrail) -> None:
        tgt = tp.target
        for trg in triggers:
            try:
                self.target.cursor().execute("%s TRIGGER %s ON %s" % (action, qualified(tgt.info.schema, trg),
                                                                     tgt.sql_name))
                self.target.commit()
            except Exception as exc:
                if action == "DISABLE":
                    raise
                audit.event("ERROR", "Could not re-enable trigger %s: %s" % (trg, exc), tgt.info.fqn)
        if triggers:
            audit.event("INFO", "%sd triggers: %s" % (action.capitalize(), ", ".join(triggers)), tgt.info.fqn)

    def _disable_target_indexes(self, tp: TablePlan, audit: AuditTrail) -> None:
        """Nonclustered indexes are rebuilt once after the load instead of maintained row by row."""
        if not self.copy_map.disable_nonclustered_indexes:
            return
        tgt = tp.target
        for name in nonclustered_indexes(self.target, tgt.info.schema, tgt.info.name):
            self.target.cursor().execute("ALTER INDEX %s ON %s DISABLE" % (quote_ident(name), tgt.sql_name))
            self.target.commit()
            self._state["indexes_disabled"].append({"schema": tgt.info.schema, "table": tgt.info.name, "name": name})
            audit.save_state(self._state)
        log.debug("%s: nonclustered indexes disabled for the load", tgt.info.fqn)

    def _rebuild_target_indexes(self, tp: TablePlan, audit: AuditTrail) -> None:
        tgt = tp.target
        for rec in list(self._state["indexes_disabled"]):
            if (rec["schema"].lower(), rec["table"].lower()) != (tgt.info.schema.lower(), tgt.info.name.lower()):
                continue
            if index_disabled(self.target, rec["schema"], rec["table"], rec["name"]):
                log.info("Rebuilding index %s on %s", rec["name"], tgt.info.fqn)
                self.target.cursor().execute("ALTER INDEX %s ON %s REBUILD" % (quote_ident(rec["name"]),
                                                                               tgt.sql_name))
                self.target.commit()
            self._state["indexes_disabled"].remove(rec)
            audit.save_state(self._state)

    def _check_row_count(self, tp: TablePlan, source_rows: int) -> None:
        cur = self.target.cursor()
        cur.execute("SELECT COUNT_BIG(*) FROM %s" % tp.target.sql_name)  # nosec B608
        n = int(cur.fetchone()[0])
        self.target.commit()
        if n != source_rows:
            raise TableFailed("target %s has %d rows but the source had %d: the source changed during the copy "
                              "(copy from a restored backup or a database snapshot)" % (tp.target.info.fqn, n,
                                                                                       source_rows))

    def _target_distinct(self, tp: TablePlan, cp) -> int:
        tc = cp.target_info
        cur = self.target.cursor()
        cur.execute("SELECT COUNT_BIG(*) FROM (SELECT 1 AS x FROM %s AS t WHERE t.%s IS NOT NULL GROUP BY %s) AS z"  # nosec B608
                    % (tp.target.sql_name, quote_ident(tc.name), hash_expr("t", tc)))
        n = int(cur.fetchone()[0])
        self.target.commit()
        return n

    # ------------------------------------------------------------------ load
    def _load(self, tp: TablePlan, run_id: str, audit: AuditTrail, prog: Dict[str, Any]) -> int:
        set_based = self._plan_transfer == "set_based"
        session = self.work if set_based else self.target   # the session that inserts the rows
        name = tp.target.full_name if set_based else tp.target.sql_name
        if tp.target.identity_insert:
            session.cursor().execute(identity_insert_sql(name, True))
        try:
            if tp.strategy == "chunked":
                return self._load_chunked(tp, run_id, audit, prog, set_based, session)
            return self._load_range(tp, run_id, audit, set_based, session, None, None, "COMPLETED")[1]
        finally:
            if tp.target.identity_insert:
                session.cursor().execute(identity_insert_sql(name, False))

    def _load_chunked(self, tp, run_id, audit, prog, set_based: bool, session) -> int:
        key_is_int = tp.key_info.family == "int"
        last = prog.get("last_key")
        if last is not None:
            last = int(last) if key_is_int else last
            log.info("Resuming %s after key %s", tp.fqn, last)
        total, t0 = 0, time.time()
        while True:
            upper, n = self._load_range(tp, run_id, audit, set_based, session, last, tp.batch_size, "IN_PROGRESS")
            if upper is None:
                break
            last, total = upper, total + n
            log.info("  %s: %d rows copied so far (key <= %s, %.0f rows/s)", tp.fqn, total, last,
                     total / max(time.time() - t0, 0.001))
        cur = session.cursor()
        cur.execute(audit.progress_upsert_sql(self._audit_db if set_based else None),
                    audit.progress_params(run_id, tp.info.schema, tp.info.name, "COMPLETED", last, 0))
        session.commit()
        return total

    def _load_range(self, tp, run_id, audit, set_based: bool, session, lower, batch: Optional[int], status: str):
        """One committed unit: the next key range (batch rows) or, with batch None, the whole table."""
        def work():
            ranged = batch is not None
            params: List[Any] = []
            upper = None
            if ranged:
                cur = self.read.cursor()
                cur.execute(chunk_bound_sql(tp, lower is not None), [batch] + ([lower] if lower is not None else []))
                upper = cur.fetchone()[0]
                if upper is None:
                    return None, 0
                params = ([lower] if lower is not None else []) + [upper]
            if set_based:
                cur = session.cursor()
                cur.execute(copy_insert_sql(tp, ranged, lower is not None), params)
                n = max(cur.rowcount, 0)
            else:
                n = self._stream(tp, copy_select_sql(tp, True, ranged, lower is not None), params)
            if audit.db_enabled:
                session.cursor().execute(audit.progress_upsert_sql(self._audit_db if set_based else None),
                                         audit.progress_params(run_id, tp.info.schema, tp.info.name, status, upper, n))
            session.commit()
            self._data_changed = True
            return upper, n

        return with_retry(work, session, int(self.ex.get("max_retries", 3)),
                          float(self.ex.get("retry_backoff_seconds", 2)), "copy of %s" % tp.fqn)

    def _stream(self, tp: TablePlan, sql: str, params: List[Any]) -> int:
        """Rows (already masked by the source session) -> target, in batches; reading overlaps writing."""
        cur = self.target.cursor()
        cur.fast_executemany = True
        sizes = _input_sizes(tp)
        if sizes is not None:
            cur.setinputsizes(sizes)
        insert = stream_insert_sql(tp)
        n = 0
        batches = _read_ahead(self.work, sql, params, _rows_per_insert(tp, int(self.ex.get("fetch_size", 20000))))
        try:
            for rows in batches:
                cur.executemany(insert, rows)
                n += len(rows)
        finally:
            batches.close()   # stops the reader thread at once if the write failed
            self.work.commit()   # ends the source read transaction (nothing was written there)
        return n


#: written as streamed (data-at-execution) parameters: fast_executemany would otherwise reserve the
#: maximum possible size (2 GB) for every row of these types and run out of memory
_LOB_TEXT = {"text", "ntext", "xml"}
_LOB_BINARY = {"image"} | UDT_TYPES


def _is_lob(ci) -> bool:
    t = ci.data_type.lower()
    return t in _LOB_TEXT or t in _LOB_BINARY or ci.max_length == -1


def _input_sizes(tp: TablePlan):
    """Parameter types for the streamed INSERT.  Masked and date values are sent as text and converted by
    the target, exactly like an UPDATE in place; large values are streamed instead of pre-allocated."""
    try:
        import pyodbc
    except ImportError:  # pragma: no cover
        return None
    text, binary = pyodbc.SQL_WVARCHAR, pyodbc.SQL_VARBINARY
    sizes = []
    for c in tp.target.columns:
        tc, t = c.target, c.target.data_type.lower()
        if c.masked is not None and not c.masked.is_nullify:
            if tc.family != "string":
                sizes.append((text, 100, 0))
            else:
                sizes.append((text, tc.max_chars if tc.max_chars and tc.max_chars > 0 else 0, 0))
        elif c.masked is None and travels_as_text(c.source):
            sizes.append((text, DATE_TEXT_LEN, 0))
        elif _is_lob(tc):
            is_binary = t in _LOB_BINARY or t in ("varbinary", "binary")
            sizes.append((binary if is_binary else text, 0, 0))
        else:
            sizes.append(None)
    return sizes


def _row_bytes(tp: TablePlan) -> int:
    total = 0
    for c in tp.target.columns:
        tc = c.target
        if _is_lob(tc):
            total += 16384    # streamed, but the fetched rows are held in memory meanwhile
        elif tc.family == "string":
            total += 2 * (tc.max_chars or 0) + 2
        else:
            total += max(tc.max_length, 8) + 8
    return max(total, 1)


def _rows_per_insert(tp: TablePlan, fetch_size: int) -> int:
    return max(100, min(fetch_size, STREAM_BATCH_BYTES // _row_bytes(tp)))


def _read_ahead(conn, sql: str, params: List[Any], size: int) -> Iterator[List[tuple]]:
    """Fetch batches on a background thread (one batch ahead) while the caller writes the previous one."""
    q: queue.Queue[Any] = queue.Queue(maxsize=2)
    stop = threading.Event()
    done = object()
    cur = conn.cursor()

    def reader():
        try:
            cur.execute(sql, params)
            while not stop.is_set():
                rows = cur.fetchmany(size)
                if not rows:
                    break
                _put(q, [tuple(r) for r in rows], stop)
            _put(q, done, stop)
        except BaseException as exc:  # handed to the caller, which re-raises it
            _put(q, exc, stop)

    thread = threading.Thread(target=reader, name="deid-read-ahead", daemon=True)
    thread.start()
    try:
        while True:
            item = q.get()
            if item is done:
                return
            if isinstance(item, BaseException):
                raise item
            yield item
    finally:
        stop.set()
        if thread.is_alive():
            try:
                cur.cancel()   # abandon the rest of the result set
            except Exception as exc:
                log.debug("Cancelling the read failed: %s", exc.__class__.__name__)
        while thread.is_alive():
            try:
                q.get_nowait()
            except queue.Empty:
                thread.join(0.05)
        try:
            cur.close()
        except Exception as exc:
            log.debug("Closing the read cursor failed: %s", exc.__class__.__name__)


def _put(q: queue.Queue[Any], item: Any, stop: threading.Event) -> None:
    while not stop.is_set():
        try:
            q.put(item, timeout=0.2)
            return
        except queue.Full:
            continue
