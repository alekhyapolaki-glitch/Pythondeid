"""Audit trail: run header, per-column results, events and table progress.

Written to two places:
* SQL Server tables in the ``audit.schema`` schema (default ``deid_audit``) via a
  separate autocommit connection, so audit rows survive a rolled-back table.
* Local files under ``audit/<run_id>/`` (summary.json, column_results.csv,
  events.jsonl, state.json) so evidence exists even if DB auditing is off.

No original (pre-mask) values are ever written to the audit trail.
"""

from __future__ import annotations

import csv
import datetime as _dt
import getpass
import json
import logging
import platform
import socket
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from .database.sql import quote_ident

log = logging.getLogger(__name__)

RESULT_FIELDS = [
    "run_id", "schema_name", "table_name", "column_name", "domain", "mask_type", "strategy", "batch_size", "status",
    "rows_total", "rows_non_null_before", "distinct_before", "rows_updated", "distinct_after",
    "collisions", "message", "started_at", "ended_at",
]


def new_run_id() -> str:
    return _dt.datetime.now(_dt.timezone.utc).replace(tzinfo=None).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:6]


def _now() -> _dt.datetime:
    return _dt.datetime.now(_dt.timezone.utc).replace(tzinfo=None).replace(microsecond=0)


class AuditTrail:
    def __init__(self, audit_settings: Dict[str, Any], run_id: str, conn=None):
        self.cfg = audit_settings
        self.run_id = run_id
        self.conn = conn if audit_settings.get("write_to_db", True) else None
        self.schema = audit_settings.get("schema", "deid_audit")
        self.dir = Path(audit_settings.get("output_dir", "audit")) / run_id
        self.dir.mkdir(parents=True, exist_ok=True)
        self.results: List[Dict[str, Any]] = []
        self.summary: Dict[str, Any] = {"run_id": run_id}

    # ------------------------------------------------------------------ DDL
    @property
    def db_enabled(self) -> bool:
        return self.conn is not None

    def t(self, name: str) -> str:
        return "%s.%s" % (quote_ident(self.schema), quote_ident(name))

    def ensure_schema(self) -> None:
        if not self.db_enabled:
            return
        s = self.schema.replace("'", "''")
        cur = self.conn.cursor()
        cur.execute("IF SCHEMA_ID(N'%s') IS NULL EXEC(N'CREATE SCHEMA %s')" % (s, quote_ident(self.schema)))
        ddl = {
            "run": """
                run_id NVARCHAR(64) NOT NULL PRIMARY KEY, mode NVARCHAR(20) NOT NULL, status NVARCHAR(20) NOT NULL,
                started_at DATETIME2(0) NOT NULL, ended_at DATETIME2(0) NULL, server_name NVARCHAR(256) NULL,
                database_name NVARCHAR(256) NULL, db_login NVARCHAR(256) NULL, os_user NVARCHAR(256) NULL,
                client_host NVARCHAR(256) NULL, tool_version NVARCHAR(32) NULL, rules_file NVARCHAR(512) NULL,
                rules_hash NVARCHAR(64) NULL, key_fingerprint NVARCHAR(64) NULL, resumed_from NVARCHAR(64) NULL,
                tables_planned INT NULL, tables_completed INT NULL, rows_updated BIGINT NULL,
                message NVARCHAR(MAX) NULL, algorithm_version INT NULL""",
            "column_result": """
                id BIGINT IDENTITY(1,1) PRIMARY KEY, run_id NVARCHAR(64) NOT NULL, schema_name SYSNAME NOT NULL,
                table_name SYSNAME NOT NULL, column_name SYSNAME NOT NULL, domain NVARCHAR(128) NULL,
                mask_type NVARCHAR(64) NULL, strategy NVARCHAR(20) NULL, batch_size INT NULL,
                status NVARCHAR(20) NOT NULL,
                rows_total BIGINT NULL, rows_non_null_before BIGINT NULL, distinct_before BIGINT NULL,
                rows_updated BIGINT NULL, distinct_after BIGINT NULL, collisions BIGINT NULL,
                message NVARCHAR(MAX) NULL, started_at DATETIME2(0) NULL, ended_at DATETIME2(0) NULL""",
            "event": """
                id BIGINT IDENTITY(1,1) PRIMARY KEY, run_id NVARCHAR(64) NOT NULL, ts DATETIME2(0) NOT NULL,
                level NVARCHAR(10) NOT NULL, object_name NVARCHAR(512) NULL, message NVARCHAR(MAX) NOT NULL""",
            "table_progress": """
                run_id NVARCHAR(64) NOT NULL, schema_name SYSNAME NOT NULL, table_name SYSNAME NOT NULL,
                status NVARCHAR(20) NOT NULL, last_key NVARCHAR(4000) NULL, rows_updated BIGINT NOT NULL DEFAULT 0,
                updated_at DATETIME2(0) NOT NULL,
                CONSTRAINT PK_deid_table_progress PRIMARY KEY (run_id, schema_name, table_name)""",
        }
        for name, cols in ddl.items():
            obj = "%s.%s" % (s, name)
            cur.execute("IF OBJECT_ID(N'%s', N'U') IS NULL CREATE TABLE %s (%s)" % (obj, self.t(name), cols))
        # upgrade audit tables created by earlier versions
        for table, col, typ in (("run", "algorithm_version", "INT"), ("column_result", "batch_size", "INT")):
            cur.execute("IF COL_LENGTH(N'%s.%s', N'%s') IS NULL ALTER TABLE %s ADD %s %s NULL"
                        % (s, table, col, self.t(table), quote_ident(col), typ))

    # ------------------------------------------------------------------ run
    def start_run(self, mode: str, info: Dict[str, Any]) -> None:
        self.summary.update(info)
        self.summary.update({
            "mode": mode, "status": "RUNNING", "started_at": _now().isoformat(),
            "os_user": getpass.getuser(), "client_host": socket.gethostname(), "platform": platform.platform(),
        })
        self._write_summary()
        if self.db_enabled:
            self.conn.cursor().execute(
                "INSERT INTO %s (run_id, mode, status, started_at, server_name, database_name, db_login, os_user, "  # nosec B608
                "client_host, tool_version, rules_file, rules_hash, key_fingerprint, resumed_from, tables_planned, "
                "algorithm_version) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)" % self.t("run"),
                [self.run_id, mode, "RUNNING", _now(), info.get("server"), info.get("database"), info.get("login"),
                 self.summary["os_user"], self.summary["client_host"], info.get("tool_version"),
                 info.get("rules_file"), info.get("rules_hash"), info.get("key_fingerprint"),
                 info.get("resumed_from"), info.get("tables_planned"), info.get("algorithm_version")],
            )
        self.event("INFO", "Run started (mode=%s)" % mode)

    def end_run(self, status: str, message: str = "", tables_completed: int = 0, rows_updated: int = 0) -> None:
        self.summary.update({
            "status": status, "ended_at": _now().isoformat(), "message": message,
            "tables_completed": tables_completed, "rows_updated": rows_updated,
        })
        self._write_summary()
        self._write_results_csv()
        if self.db_enabled:
            try:
                self.conn.cursor().execute(
                    "UPDATE %s SET status=?, ended_at=?, message=?, tables_completed=?, rows_updated=? WHERE run_id=?"  # nosec B608
                    % self.t("run"),
                    [status, _now(), message[:4000], tables_completed, rows_updated, self.run_id],
                )
            except Exception as exc:
                log.error("Could not write run status to audit table: %s", exc)
        self.event("INFO", "Run finished with status %s. %s" % (status, message))

    # ------------------------------------------------------------------ events/results
    def event(self, level: str, message: str, obj: Optional[str] = None) -> None:
        rec = {"ts": _now().isoformat(), "level": level, "object": obj, "message": message}
        with (self.dir / "events.jsonl").open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec) + "\n")
        if self.db_enabled:
            try:
                self.conn.cursor().execute(
                    "INSERT INTO %s (run_id, ts, level, object_name, message) VALUES (?,?,?,?,?)" % self.t("event"),  # nosec B608
                    [self.run_id, _now(), level, obj, message],
                )
            except Exception as exc:
                log.error("Could not write audit event: %s", exc)

    def column_result(self, rec: Dict[str, Any]) -> None:
        rec = dict({k: None for k in RESULT_FIELDS}, **rec, run_id=self.run_id)
        self.results.append(rec)
        self._write_results_csv()
        if self.db_enabled:
            cols = RESULT_FIELDS
            values = [rec[c][:4000] if c == "message" and isinstance(rec[c], str) else rec[c] for c in cols]
            try:
                self.conn.cursor().execute(
                    "INSERT INTO %s (%s) VALUES (%s)" % (self.t("column_result"), ",".join(cols), ",".join("?" * len(cols))),  # nosec B608
                    values,
                )
            except Exception as exc:
                log.error("Could not write column result to audit table: %s", exc)

    FILE_FIELDS = ["run_id", "rule", "format", "status", "input_path", "input_sha256", "output_path",
                   "output_sha256", "sheets", "rows", "masked_cells", "value_errors", "formulas_skipped",
                   "seconds", "message"]

    def file_result(self, rec: Dict[str, Any]) -> None:
        """Per-file outcome of a file de-identification run (no data values, only counts and fingerprints)."""
        rec = dict({k: None for k in self.FILE_FIELDS}, **rec, run_id=self.run_id)
        self.summary.setdefault("files", []).append(rec)
        self._write_summary()
        with (self.dir / "file_results.csv").open("w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=self.FILE_FIELDS)
            w.writeheader()
            for r in self.summary["files"]:
                w.writerow({k: (json.dumps(r[k]) if isinstance(r.get(k), (dict, list)) else r.get(k))
                            for k in self.FILE_FIELDS})

    # ------------------------------------------------------------------ progress / checkpoints
    def progress_upsert_sql(self) -> str:
        """SQL executed on the *work* connection so the checkpoint commits atomically with the data."""
        t = self.t("table_progress")
        return (
            "UPDATE %s SET status=?, last_key=?, rows_updated=rows_updated+?, updated_at=SYSUTCDATETIME() "  # nosec B608
            "WHERE run_id=? AND schema_name=? AND table_name=?; "
            "IF @@ROWCOUNT = 0 INSERT INTO %s (run_id, schema_name, table_name, status, last_key, rows_updated, updated_at) "
            "VALUES (?,?,?,?,?,?,SYSUTCDATETIME());" % (t, t)
        )

    @staticmethod
    def progress_params(run_id, schema, table, status, last_key, rows) -> List[Any]:
        lk = None if last_key is None else str(last_key)
        return [status, lk, rows, run_id, schema, table, run_id, schema, table, status, lk, rows]

    def table_progress(self, run_id: str) -> Dict[tuple, Dict[str, Any]]:
        if not self.db_enabled:
            return {}
        cur = self.conn.cursor()
        cur.execute(
            "SELECT schema_name, table_name, status, last_key, rows_updated FROM %s WHERE run_id = ?" % self.t("table_progress"),  # nosec B608
            [run_id],
        )
        return {
            (r[0].lower(), r[1].lower()): {"status": r[2], "last_key": r[3], "rows_updated": int(r[4] or 0)}
            for r in cur.fetchall()
        }

    def previous_runs(self, limit: int = 20) -> List[Dict[str, Any]]:
        if not self.db_enabled:
            return []
        cur = self.conn.cursor()
        cur.execute(
            "SELECT TOP (?) run_id, mode, status, started_at, ended_at, rules_hash, key_fingerprint, rows_updated, message "  # nosec B608
            "FROM %s ORDER BY started_at DESC" % self.t("run"),
            [limit],
        )
        cols = [d[0] for d in cur.description]
        return [dict(zip(cols, r)) for r in cur.fetchall()]

    def copy_progress(self, from_run: str) -> None:
        """When resuming, carry the old run's checkpoints over to the new run id."""
        if not self.db_enabled:
            return
        t = self.t("table_progress")
        self.conn.cursor().execute(
            "INSERT INTO %s (run_id, schema_name, table_name, status, last_key, rows_updated, updated_at) "  # nosec B608
            "SELECT ?, src.schema_name, src.table_name, src.status, src.last_key, src.rows_updated, src.updated_at "
            "FROM %s AS src WHERE src.run_id = ? AND NOT EXISTS (SELECT 1 FROM %s AS x WHERE x.run_id = ? "
            "AND x.schema_name = src.schema_name AND x.table_name = src.table_name)" % (t, t, t),
            [self.run_id, from_run, self.run_id],
        )

    # ------------------------------------------------------------------ local state
    def save_state(self, state: Dict[str, Any]) -> None:
        with (self.dir / "state.json").open("w", encoding="utf-8") as fh:
            json.dump(state, fh, indent=2, default=str)

    @staticmethod
    def load_state(output_dir: str, run_id: str) -> Dict[str, Any]:
        p = Path(output_dir) / run_id / "state.json"
        if not p.exists():
            return {}
        with p.open(encoding="utf-8") as fh:
            return json.load(fh)

    def _write_summary(self) -> None:
        with (self.dir / "summary.json").open("w", encoding="utf-8") as fh:
            json.dump(dict(self.summary, columns=self.results), fh, indent=2, default=str)

    def _write_results_csv(self) -> None:
        with (self.dir / "column_results.csv").open("w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=RESULT_FIELDS)
            w.writeheader()
            for r in self.results:
                w.writerow({k: r.get(k) for k in RESULT_FIELDS})
