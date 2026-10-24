"""On-the-fly masking against a real SQL Server (skipped unless DEID_IT_SERVER is set).

DEID_IT_SERVER2 (optional, e.g. localhost,1434) is a second instance for the cross-server test:
    docker run -d --name mssql2 -e ACCEPT_EULA=Y -e "MSSQL_SA_PASSWORD=Deid_Test_Pass1!" -p 1434:1433 \
        mcr.microsoft.com/mssql/server:2022-latest

Every copy is compared with the same database masked in place: both modes must give identical values.
"""

import json
import os

import pytest

from deid.config import Rules, load_rules, parse_copy_map, validate_connection
from deid.database.connection import ConnectionFactory, acquire_run_lock
from deid.engine import CopyEngine, RunLocked
from deid.engine.copy_sql import UNMAPPED_MESSAGE
from deid.masking import KeyRing

from .test_integration_sqlserver import KEY, ROOT, _create_db, _mask, _query

pytestmark = pytest.mark.skipif(not os.environ.get("DEID_IT_SERVER"), reason="DEID_IT_SERVER not set")

TABLES = {"Customers": "CustomerId", "Accounts": "AccountNumber", "Transactions": "TxnId", "Visits": "VisitId",
          "MarketingContacts": "Email, Notes"}


def _db(name, server=None):
    return validate_connection({
        "server": server or os.environ["DEID_IT_SERVER"], "database": name, "auth": "sql",
        "username": os.environ.get("DEID_IT_USER", "sa"), "password_env": "DEID_IT_PASSWORD",
        "trust_server_certificate": True}, "integration test")


def _rules(tables=None) -> Rules:
    rules = load_rules(str(ROOT / "config" / "deid_rules.yaml"))
    if tables:
        rules.tables = [t for t in rules.tables if t.table in tables]
    return rules


def _engine(src_settings, target_db, rules=None, **copy_map):
    rules = rules or _rules()
    return CopyEngine(src_settings, rules, KeyRing.from_string(KEY),
                      ConnectionFactory(src_settings.database, interactive=False),
                      ConnectionFactory(target_db, interactive=False), parse_copy_map(copy_map, rules), "tgt")


def _copy(engine, resume_from=None):
    try:
        info = engine.connect()
        plan = engine.plan()
        assert plan.ok, plan.errors
        if resume_from is None:
            assert engine.execute(plan, dry_run=True, info=info)["status"] == "DRY_RUN_OK"
        return plan, engine.execute(plan, dry_run=False, info=info, resume_from=resume_from)
    finally:
        engine.close()


def _plan_errors(engine):
    try:
        engine.connect()
        return engine.plan().errors
    finally:
        engine.close()


def _connect(db):
    return ConnectionFactory(db, interactive=False).connect(autocommit=True)


def _rows(db, table, target_table=None, skip=("CreatedAt",)):
    conn = _connect(db)
    try:
        cols = [r[0] for r in conn.cursor().execute(
            "SELECT name FROM sys.columns WHERE object_id = OBJECT_ID(?) AND system_type_id <> 189 ORDER BY column_id",
            ["dbo." + table]).fetchall() if r[0] not in skip]
        sql = "SELECT %s FROM dbo.[%s] ORDER BY %s" % (
            ", ".join("CAST([%s] AS NVARCHAR(400))" % c for c in cols), target_table or table, TABLES[table])
        return [tuple(r) for r in conn.cursor().execute(sql).fetchall()]
    finally:
        conn.close()


def _snapshot(db, **kw):
    return {t: _rows(db, t, **kw) for t in TABLES}


def _target_health(db):
    """(untrusted or disabled FKs, disabled indexes, disabled triggers) in the target."""
    conn = _connect(db)
    try:
        q = conn.cursor()
        return (q.execute("SELECT COUNT(*) FROM sys.foreign_keys WHERE is_disabled = 1 OR is_not_trusted = 1").fetchone()[0],
                q.execute("SELECT COUNT(*) FROM sys.indexes WHERE is_disabled = 1").fetchone()[0],
                q.execute("SELECT COUNT(*) FROM sys.triggers WHERE is_disabled = 1").fetchone()[0])
    finally:
        conn.close()


@pytest.fixture(scope="module")
def in_place(tmp_path_factory):
    """The reference: the sample database masked in place."""
    settings = _create_db(tmp_path_factory.mktemp("ip"), "DeidCopyRef")
    assert _mask(settings)["status"] == "SUCCEEDED"
    return _snapshot(settings.database)


@pytest.mark.parametrize("transfer", ["set_based", "stream"])
def test_copy_matches_in_place_and_leaves_source_untouched(tmp_path, in_place, transfer):
    src = _create_db(tmp_path, "DeidCopySrc")
    tgt = _create_db(tmp_path, "DeidCopyTgt").database     # target already holds rows: emptied first
    before = _snapshot(src.database, skip=())
    plan, result = _copy(_engine(src, tgt, transfer=transfer))
    assert plan.copy.transfer == transfer
    assert result["status"] == "SUCCEEDED", result["failures"]
    assert _snapshot(tgt) == in_place                      # identical to in-place masking
    assert _snapshot(src.database, skip=()) == before      # the source is never changed ...
    assert _query(src, "SELECT SCHEMA_ID('deid_audit')")[0][0] is None   # ... not even audit tables
    assert _rows(tgt, "Customers", skip=())[0][-1] == before["Customers"][0][-1]   # as-is column copied
    assert _target_health(tgt) == (0, 0, 0)                # FKs trusted (WITH CHECK), indexes and triggers on


def _create_remote_db(name):
    """The sample database (with its rows, so the target is emptied first) on the second instance."""
    import re
    conn = _connect(_db("master", os.environ["DEID_IT_SERVER2"]))
    cur = conn.cursor()
    cur.execute("IF DB_ID('%s') IS NOT NULL BEGIN ALTER DATABASE [%s] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; "
                "DROP DATABASE [%s]; END" % (name, name, name))
    script = (ROOT / "sql" / "sample_schema.sql").read_text(encoding="utf-8").replace("DeidDemo", name)
    for batch in re.split(r"^\s*GO\s*$", script, flags=re.M | re.I):
        if batch.strip():
            cur.execute(batch)
            while cur.nextset():
                pass
    conn.close()
    return _db(name, os.environ["DEID_IT_SERVER2"])


@pytest.mark.skipif(not os.environ.get("DEID_IT_SERVER2"), reason="DEID_IT_SERVER2 not set")
def test_copy_to_another_server(tmp_path, in_place):
    src = _create_db(tmp_path, "DeidCopySrc2")
    tgt = _create_remote_db("DeidCopyRemote")
    plan, result = _copy(_engine(src, tgt))
    assert plan.copy.transfer == "stream"                  # auto: different instance
    assert result["status"] == "SUCCEEDED", result["failures"]
    assert _snapshot(tgt) == in_place
    assert _target_health(tgt) == (0, 0, 0)


def test_copy_into_other_table_of_same_database_with_column_map(tmp_path, in_place):
    src = _create_db(tmp_path, "DeidCopySame")
    conn = _connect(src.database)
    conn.cursor().execute(
        "CREATE TABLE dbo.Customers_Masked (CustomerId INT IDENTITY PRIMARY KEY, FirstName NVARCHAR(50) NOT NULL, "
        "LastName NVARCHAR(50) NOT NULL, EmailAddress VARCHAR(100) NULL, SSN CHAR(11) NULL, Phone VARCHAR(20) NULL, "
        "Street NVARCHAR(100) NULL, City NVARCHAR(50) NULL, Zip VARCHAR(10) NULL, DateOfBirth DATE NULL, "
        "MemberNo BIGINT NULL, CreatedAt DATETIME2(0) NOT NULL DEFAULT SYSUTCDATETIME())")
    conn.close()
    columns = ["CustomerId", "FirstName", "LastName", "Email", "SSN", "Phone", "Street", "City", "Zip",
               "DateOfBirth", "MemberNo"]                    # CreatedAt left out: the target default fills it
    engine = _engine(src, src.database, _rules(["Customers"]), tables=[{
        "source": "dbo.Customers", "target": "dbo.Customers_Masked", "columns": columns,
        "column_map": {"Email": "EmailAddress"}}])
    plan, result = _copy(engine)
    assert plan.copy.transfer == "set_based" and result["status"] == "SUCCEEDED", result["failures"]
    got = [tuple(r) for r in _query(src, "SELECT %s FROM dbo.Customers_Masked ORDER BY CustomerId" % ", ".join(
        "CAST([%s] AS NVARCHAR(400))" % ("EmailAddress" if c == "Email" else c) for c in columns))]
    assert got == in_place["Customers"]
    assert _query(src, "SELECT Email FROM dbo.Customers WHERE CustomerId = 1")[0][0] == "John.Doe@Mail.com"


def test_value_added_after_the_map_fails_instead_of_leaking(tmp_path, monkeypatch, in_place):
    """A source row that appears mid-copy has no mask: the copy stops, the original never reaches the target."""
    src = _create_db(tmp_path, "DeidCopyRace")
    tgt = _create_db(tmp_path, "DeidCopyRaceTgt").database
    original = CopyEngine._build_map

    def build_map_then_insert(self, tp, write):
        stats = original(self, tp, write)
        if tp.info.name == "Customers" and write:
            conn = _connect(src.database)
            conn.cursor().execute("INSERT dbo.Customers (FirstName, LastName, Email) VALUES "
                                  "(N'Late', N'Arrival', 'late.arrival@example.com')")
            conn.close()
        return stats

    monkeypatch.setattr(CopyEngine, "_build_map", build_map_then_insert)
    _, result = _copy(_engine(src, tgt))
    assert result["status"] == "PARTIAL"
    assert UNMAPPED_MESSAGE in " ".join(result["failures"])
    leaked = _query(src, "SELECT COUNT(*) FROM DeidCopyRaceTgt.dbo.Customers WHERE Email = 'late.arrival@example.com' "
                         "OR FirstName = N'Late' OR Email IN (SELECT Email FROM DeidCopyRace.dbo.Customers)")
    assert leaked[0][0] == 0
    # a fresh run reloads everything (the new row is masked now) and validates the FKs again
    monkeypatch.setattr(CopyEngine, "_build_map", original)
    _, result = _copy(_engine(src, tgt))
    assert result["status"] == "SUCCEEDED", result["failures"]
    assert _target_health(tgt) == (0, 0, 0)
    assert len(_rows(tgt, "Customers")) == 5


def test_resume_continues_after_the_last_committed_chunk(tmp_path, monkeypatch, in_place):
    src = _create_db(tmp_path, "DeidCopyResume")
    tgt = _create_db(tmp_path, "DeidCopyResumeTgt").database
    original = CopyEngine._load_range
    calls = {"n": 0}

    def fail_once(self, tp, *a, **k):
        if tp.info.name == "Transactions":
            calls["n"] += 1
            if calls["n"] == 2:
                raise RuntimeError("simulated outage")
        return original(self, tp, *a, **k)

    monkeypatch.setattr(CopyEngine, "_load_range", fail_once)
    _, first = _copy(_engine(src, tgt))
    assert first["status"] == "PARTIAL"
    _, resumed = _copy(_engine(src, tgt), resume_from=first["run_id"])
    assert resumed["status"] == "SUCCEEDED", resumed["failures"]
    assert _snapshot(tgt) == in_place                      # no chunk lost or loaded twice
    assert _target_health(tgt) == (0, 0, 0)


def test_unsafe_targets_are_refused_before_anything_is_written(tmp_path):
    src = _create_db(tmp_path, "DeidCopyRefuse")
    tgt = _create_db(tmp_path, "DeidCopyRefuseTgt").database
    errors = " ".join(_plan_errors(_engine(src, src.database)))
    assert "target is the source table itself" in errors
    # Transactions is not copied but its target rows reference Accounts, which would be emptied
    errors = " ".join(_plan_errors(_engine(src, tgt, _rules(["Customers", "Accounts"]))))
    assert "dbo.Transactions is not copied but has" in errors
    errors = " ".join(_plan_errors(_engine(src, tgt, on_existing_rows="error")))
    assert "not empty and on_existing_rows is 'error'" in errors
    conn = _connect(tgt)
    conn.cursor().execute("ALTER TABLE dbo.MarketingContacts ADD Region NVARCHAR(10) NOT NULL DEFAULT N'x'")
    conn.cursor().execute("ALTER TABLE dbo.Visits ADD Ward NVARCHAR(10) NULL")
    conn.cursor().execute("ALTER TABLE dbo.Accounts ADD Branch INT NULL")
    conn.cursor().execute("UPDATE dbo.Accounts SET Branch = 1")
    conn.cursor().execute("ALTER TABLE dbo.Accounts ALTER COLUMN Branch INT NOT NULL")
    conn.close()
    errors = " ".join(_plan_errors(_engine(src, tgt)))
    assert "Accounts.Branch is NOT NULL without a default" in errors
    assert "Region" not in errors and "Ward" not in errors   # defaults / nullable are fine


def test_concurrent_run_on_the_same_target_is_locked(tmp_path):
    src = _create_db(tmp_path, "DeidCopyLock")
    tgt = _create_db(tmp_path, "DeidCopyLockTgt").database
    holder = _connect(tgt)
    assert acquire_run_lock(holder, "pythondeid:DeidCopyLockTgt")
    engine = _engine(src, tgt)
    try:
        info = engine.connect()
        with pytest.raises(RunLocked):
            engine.execute(engine.plan(), dry_run=False, info=info)
    finally:
        engine.close()
        holder.close()


def test_refresh_on_the_fly(tmp_path, monkeypatch):
    """refresh with execution.mode on_the_fly: exit 0 every time (the target is reloaded, never 'already masked')."""
    import yaml

    from deid.cli import main
    _create_db(tmp_path, "DeidCopyRefresh")
    _create_db(tmp_path, "DeidCopyRefreshTgt")
    conns = {"default": "src", "connections": {"src": _db("DeidCopyRefresh"), "tgt": _db("DeidCopyRefreshTgt")}}
    (tmp_path / "connections.yaml").write_text(yaml.safe_dump(conns), encoding="utf-8")
    (tmp_path / "copy_map.yaml").write_text("target_connection: tgt\n", encoding="utf-8")
    (tmp_path / "settings.yaml").write_text("execution:\n  mode: on_the_fly\n", encoding="utf-8")
    (tmp_path / "paths.yaml").write_text(yaml.safe_dump({
        "rules_file": str(ROOT / "config" / "deid_rules.yaml"), "copy_map": str(tmp_path / "copy_map.yaml"),
        "audit_dir": str(tmp_path / "audit"), "log_dir": str(tmp_path / "logs"),
        "run_results_dir": str(tmp_path / "results")}), encoding="utf-8")
    monkeypatch.setenv("DEID_SECRET_KEY", KEY)
    args = ["--settings", str(tmp_path / "settings.yaml"), "--connections", str(tmp_path / "connections.yaml"),
            "--paths", str(tmp_path / "paths.yaml"), "refresh"]
    for _ in range(2):
        assert main(args) == 0
        result = json.loads((tmp_path / "results" / "latest_default.json").read_text(encoding="utf-8"))
        assert result["status"] == "SUCCEEDED" and result["mode"] == "on_the_fly"
        assert result["target"]["database"] == "DeidCopyRefreshTgt"


def test_stream_carries_every_type_exactly(tmp_path):
    """Values copied as-is between sessions must not lose precision (time/datetime2(7), offsets, CLR types)."""
    src = _create_db(tmp_path, "DeidCopyTypes")
    tgt = _create_db(tmp_path, "DeidCopyTypesTgt").database
    ddl = ("CREATE TABLE dbo.Kinds (Id INT PRIMARY KEY, Email VARCHAR(100) NULL, T TIME(7), D2 DATETIME2(7), "
           "O DATETIMEOFFSET(7), DT DATETIME, M MONEY, F FLOAT, G GEOGRAPHY, H HIERARCHYID, X XML, "
           "B VARBINARY(MAX), N NVARCHAR(MAX), U UNIQUEIDENTIFIER, RV ROWVERSION, C AS (Id + 1))")
    for db in (src.database, tgt):
        conn = _connect(db)
        conn.cursor().execute(ddl)
        conn.close()
    conn = _connect(src.database)
    conn.cursor().execute(
        "INSERT dbo.Kinds (Id, Email, T, D2, O, DT, M, F, G, H, X, B, N, U) VALUES "
        "(1, 'a@b.com', '12:34:56.1234567', '2021-06-07 08:09:10.1234567', '2020-01-02 03:04:05.1234567 +05:30', "
        "'2019-02-03T04:05:06.997', 12.3456, 0.1, geography::Point(47.6, -122.3, 4326), hierarchyid::Parse('/1/2/'), "
        "N'<a i=\"1\"/>', 0x00FF10, REPLICATE(CAST(N'z' AS NVARCHAR(MAX)), 9000), NEWID()), "
        "(2, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL)")
    conn.close()
    rules = _rules(["Customers"])
    rules.tables[0].table, rules.tables[0].columns = "Kinds", [c for c in rules.tables[0].columns if c.name == "Email"]
    _, result = _copy(_engine(src, tgt, rules, transfer="stream"))
    assert result["status"] == "SUCCEEDED", result["failures"]
    as_text = ("SELECT Id, CONVERT(NVARCHAR(40), T, 126), CONVERT(NVARCHAR(40), D2, 126), CONVERT(NVARCHAR(40), O, 126), "
               "CONVERT(NVARCHAR(40), DT, 126), CONVERT(NVARCHAR(40), M, 2), CONVERT(NVARCHAR(40), F, 3), "
               "G.STAsText(), H.ToString(), CAST(X AS NVARCHAR(100)), CONVERT(NVARCHAR(100), B, 1), LEN(N), U, C "
               "FROM %s.dbo.Kinds ORDER BY Id")
    assert _query(src, as_text % "DeidCopyTypes") == _query(src, as_text % "DeidCopyTypesTgt")
    masked = _query(src, "SELECT Email FROM DeidCopyTypesTgt.dbo.Kinds WHERE Id = 1")[0][0]
    assert masked != "a@b.com" and masked.endswith("@example.com")

