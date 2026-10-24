"""SQL Server connections (pyodbc), connection strings, retries for transient errors."""

from __future__ import annotations

import getpass
import logging
import os
import re
import time
from typing import Any, Callable, Dict, Optional, TypeVar

log = logging.getLogger(__name__)
T = TypeVar("T")


class DatabaseError(Exception):
    pass


def _pyodbc():
    try:
        import pyodbc
    except ImportError as exc:  # pragma: no cover
        raise DatabaseError(
            "pyodbc is not installed in this runtime. With the ActiveState State Tool run: state install pyodbc"
        ) from exc
    # No ODBC connection pooling: a pooled connection that was used with autocommit off can come back
    # still inside a transaction although it is reopened with autocommit on (its locks and writes would
    # then hang or be lost).  The tool keeps a few long-lived connections, so pooling gains nothing.
    # Must be set before the first connection of the process.
    pyodbc.pooling = False
    return pyodbc


def _odbc_value(value: Any) -> str:
    text = str(value)
    if any(ch in text for ch in ";{}=") or text != text.strip():
        return "{" + text.replace("}", "}}") + "}"
    return text


def build_connection_string(db: Dict[str, Any], password: Optional[str] = None) -> str:
    parts = {
        "DRIVER": "{%s}" % db["driver"],
        "SERVER": db["server"],
        "DATABASE": db["database"],
        "Encrypt": "yes" if db.get("encrypt", True) else "no",
        "TrustServerCertificate": "yes" if db.get("trust_server_certificate") else "no",
        "APP": db.get("application_name") or "pythondeid",
    }
    auth = db.get("auth", "windows")
    if auth == "windows":
        parts["Trusted_Connection"] = "yes"
    elif auth == "sql":
        parts["UID"] = db["username"]
        parts["PWD"] = password or ""
    elif auth == "azure_ad_password":
        parts["Authentication"] = "ActiveDirectoryPassword"
        parts["UID"] = db["username"]
        parts["PWD"] = password or ""
    elif auth == "azure_ad_interactive":
        parts["Authentication"] = "ActiveDirectoryInteractive"
        parts["UID"] = db["username"]
    for k, v in (db.get("extra") or {}).items():
        if not re.match(r"^[A-Za-z][A-Za-z0-9 _]{0,63}$", str(k)):
            raise DatabaseError("Invalid ODBC keyword %r in connection 'extra'" % k)
        if str(k).upper() in ("PWD", "PASSWORD", "UID", "DRIVER"):
            raise DatabaseError("'extra' may not set %s; use the dedicated connection settings" % k)
        parts[str(k)] = v
    return ";".join("%s=%s" % (k, v if k == "DRIVER" else _odbc_value(v)) for k, v in parts.items()) + ";"


def resolve_password(db: Dict[str, Any], interactive: bool = True) -> Optional[str]:
    if db.get("auth") not in ("sql", "azure_ad_password"):
        return None
    env = db.get("password_env") or "DEID_DB_PASSWORD"
    pwd = os.environ.get(env)
    if pwd:
        return pwd
    if interactive:
        return getpass.getpass("Password for %s on %s: " % (db["username"], db["server"]))
    raise DatabaseError("Password environment variable %s is not set" % env)


class ConnectionFactory:
    """Creates pyodbc connections from the database settings block."""

    def __init__(self, db_settings: Dict[str, Any], interactive: bool = True):
        self.db = db_settings
        self._password = resolve_password(db_settings, interactive)

    def connect(self, autocommit: bool = False):
        pyodbc = _pyodbc()
        cs = build_connection_string(self.db, self._password)
        try:
            conn = pyodbc.connect(cs, autocommit=autocommit, timeout=int(self.db.get("login_timeout") or 30))
        except pyodbc.Error as exc:
            raise DatabaseError("Could not connect to %s/%s: %s" % (self.db["server"], self.db["database"], exc)) from exc
        if self.db.get("query_timeout"):
            conn.timeout = int(self.db["query_timeout"])
        return conn

    def describe(self) -> str:
        return "%s / %s (auth=%s)" % (self.db["server"], self.db["database"], self.db.get("auth"))


def is_transient(exc: BaseException) -> bool:
    """Deadlocks and lock timeouts can be retried on the same connection."""
    text = str(exc)
    sqlstate = exc.args[0] if getattr(exc, "args", None) else ""
    return sqlstate in ("40001",) or "1205" in text or "deadlock" in text.lower() or "(1222)" in text


def with_retry(fn: Callable[[], T], conn, retries: int, backoff: float, what: str) -> T:
    attempt = 0
    while True:
        try:
            return fn()
        except Exception as exc:
            try:
                conn.rollback()
            except Exception as rb_exc:
                log.debug("Rollback after error failed: %s", rb_exc.__class__.__name__)
            if attempt >= retries or not is_transient(exc):
                raise
            attempt += 1
            wait = backoff * (2 ** (attempt - 1))
            log.warning("Transient error during %s (attempt %d/%d), retrying in %.1fs: %s", what, attempt, retries, wait, exc)
            time.sleep(wait)


def server_info(conn) -> Dict[str, Any]:
    cur = conn.cursor()
    cur.execute(
        "SELECT @@SERVERNAME, DB_NAME(), SUSER_SNAME(), CAST(SERVERPROPERTY('ProductVersion') AS NVARCHAR(128)), "
        "CAST(SERVERPROPERTY('Edition') AS NVARCHAR(128)), HOST_NAME(), CAST(SERVERPROPERTY('ServerName') AS NVARCHAR(256))"
    )
    row = cur.fetchone()
    return {
        "server": row[0], "database": row[1], "login": row[2],
        "version": row[3], "edition": row[4], "client_host": row[5],
        "instance": row[6] or row[0],   # machine\instance as the server itself reports it
    }


def acquire_run_lock(conn, resource: str) -> bool:
    """Exclusive, session-owned application lock (sp_getapplock); held until the connection closes.

    Returns False immediately (no waiting) if another session holds it, e.g. a scheduled run overlapping a
    manual one on the same database.
    """
    cur = conn.cursor()
    cur.execute(
        "SET NOCOUNT ON; DECLARE @r INT; "
        "EXEC @r = sp_getapplock @Resource = ?, @LockMode = 'Exclusive', @LockOwner = 'Session', @LockTimeout = 0; "
        "SELECT @r;",
        [resource],
    )
    return cur.fetchone()[0] >= 0
