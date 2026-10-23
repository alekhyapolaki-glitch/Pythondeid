"""End-to-end test against a real SQL Server (skipped unless DEID_IT_SERVER is set).

    docker run -d --name mssql -e ACCEPT_EULA=Y -e "MSSQL_SA_PASSWORD=Deid_Test_Pass1!" -p 1433:1433 \
        mcr.microsoft.com/mssql/server:2022-latest
    set DEID_IT_SERVER=localhost   DEID_IT_USER=sa   DEID_IT_PASSWORD=Deid_Test_Pass1!
    python -m pytest tests/test_integration_sqlserver.py -v

It (re)creates the DeidDemo database from sql/sample_schema.sql.
"""

import os
import re
from pathlib import Path

import pytest

from deid.config import DEFAULT_SETTINGS, Settings, _deep_merge, load_rules, validate_connection
from deid.db import ConnectionFactory
from deid.engine import Engine
from deid.maskers import KeyRing

ROOT = Path(__file__).resolve().parents[1]
pytestmark = pytest.mark.skipif(not os.environ.get("DEID_IT_SERVER"), reason="DEID_IT_SERVER not set")

INTEGRITY_SQL = """
SELECT
  (SELECT COUNT(*) FROM dbo.Transactions t JOIN dbo.Accounts a ON a.AccountNumber = t.AccountNumber),
  (SELECT COUNT(*) FROM dbo.Accounts a JOIN dbo.Customers c ON REPLACE(a.OwnerSSN,'-','') = REPLACE(c.SSN,'-','')),
  (SELECT COUNT(*) FROM dbo.Transactions t JOIN dbo.Customers c ON t.NotifyEmail = c.Email),
  (SELECT COUNT(*) FROM dbo.MarketingContacts m JOIN dbo.Customers c ON m.Email = c.Email),
  (SELECT COUNT(*) FROM dbo.Accounts a JOIN dbo.Customers c ON CAST(a.MemberNo AS BIGINT) = c.MemberNo),
  (SELECT SUM(DATEDIFF(MINUTE, AdmitDate, DischargeDate)) FROM dbo.Visits),
  (SELECT SUM(DATEDIFF(DAY, c.DateOfBirth, v.AdmitDate)) FROM dbo.Visits v JOIN dbo.Customers c ON c.CustomerId = v.CustomerId)
"""
KEY = "integration-test-key-0123456789abcdefghijklmnop"


def _settings(tmp_path, database):
    db = validate_connection({
        "server": os.environ["DEID_IT_SERVER"], "database": database, "auth": "sql",
        "username": os.environ.get("DEID_IT_USER", "sa"), "password_env": "DEID_IT_PASSWORD",
        "trust_server_certificate": True,
    }, "integration test")
    raw = _deep_merge(DEFAULT_SETTINGS, {
        "database": db,
        "execution": {"batch_size": 2},
        "audit": {"output_dir": str(tmp_path / "audit")},
        "logging": {"dir": str(tmp_path / "logs")},
    })
    return Settings(**raw)


def _create_db(tmp_path, name):
    master = ConnectionFactory(_settings(tmp_path, "master").database, interactive=False).connect(autocommit=True)
    cur = master.cursor()
    cur.execute("IF DB_ID('%s') IS NOT NULL BEGIN ALTER DATABASE [%s] SET SINGLE_USER WITH ROLLBACK "
                "IMMEDIATE; DROP DATABASE [%s]; END" % (name, name, name))
    script = (ROOT / "sql" / "sample_schema.sql").read_text(encoding="utf-8").replace("DeidDemo", name)
    for batch in re.split(r"^\s*GO\s*$", script, flags=re.M | re.I):
        if batch.strip():
            cur.execute(batch)
            while cur.nextset():
                pass
    master.close()
    return _settings(tmp_path / name, name)


def _mask(settings):
    engine = Engine(settings, load_rules(str(ROOT / "config" / "deid_rules.yaml")), KeyRing.from_string(KEY),
                    ConnectionFactory(settings.database, interactive=False))
    try:
        info = engine.connect()
        plan = engine.plan()
        assert plan.ok, plan.errors
        assert engine.execute(plan, dry_run=True, info=info)["status"] == "DRY_RUN_OK"
        return engine.execute(plan, dry_run=False, info=info)
    finally:
        engine.close()


@pytest.fixture
def demo_db(tmp_path):
    return _create_db(tmp_path, "DeidDemo")


def _query(settings, sql):
    conn = ConnectionFactory(settings.database, interactive=False).connect(autocommit=True)
    try:
        return [tuple(r) for r in conn.cursor().execute(sql).fetchall()]
    finally:
        conn.close()


def test_end_to_end_preserves_integrity(demo_db):
    settings = demo_db
    before_counts = _query(settings, INTEGRITY_SQL)
    before_rows = _query(settings, "SELECT Email, SSN FROM dbo.Customers ORDER BY CustomerId")

    result = _mask(settings)

    assert result["status"] == "SUCCEEDED", result["failures"]
    assert _query(settings, INTEGRITY_SQL) == before_counts
    after_rows = _query(settings, "SELECT Email, SSN FROM dbo.Customers ORDER BY CustomerId")
    for (e0, s0), (e1, s1) in zip(before_rows, after_rows):
        if e0 is not None:
            assert e1 != e0 and e1.endswith("@example.com")
        if s0 is not None:
            assert s1 != s0 and len(s1) == len(s0)
    notes = _query(settings, "SELECT Notes FROM dbo.Visits WHERE VisitId IN (1, 2) ORDER BY VisitId")
    assert "John.Doe" not in notes[0][0] and "[PHONE]" in notes[0][0] and "123-45-6789" not in notes[1][0]
    assert _query(settings, "SELECT is_disabled FROM sys.indexes WHERE name = 'UX_Customers_SSN'") == [(False,)]
    fks = _query(settings, "SELECT name, is_disabled, is_not_trusted FROM sys.foreign_keys")
    assert all(not d and not u for _, d, u in fks)
    assert _query(settings, "SELECT status FROM deid_audit.run WHERE run_id = '%s'" % result["run_id"]) == [("SUCCEEDED",)]


def test_two_databases_mask_identically(tmp_path):
    """Same key + rules => byte-identical masked values in independently masked databases."""
    a, b = _create_db(tmp_path, "DeidDemoA"), _create_db(tmp_path, "DeidDemoB")
    assert _mask(a)["status"] == "SUCCEEDED" and _mask(b)["status"] == "SUCCEEDED"
    for sql in ("SELECT * FROM dbo.Customers ORDER BY CustomerId", "SELECT * FROM dbo.Accounts ORDER BY CustomerId, Balance",
                "SELECT * FROM dbo.Transactions ORDER BY TxnId", "SELECT * FROM dbo.Visits ORDER BY VisitId"):
        rows_a = [r[:-1] if "Customers" in sql else r for r in _query(a, sql)]  # drop CreatedAt default
        rows_b = [r[:-1] if "Customers" in sql else r for r in _query(b, sql)]
        assert rows_a == rows_b, sql
