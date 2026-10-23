from deid.config import parse_rules
from deid.engine import build_plan, check_fits, distinct_values_sql, update_sql
from deid.schema import ColumnInfo, ForeignKey, SchemaCatalog, TableInfo

EX = {"auto_include_fk_columns": True}


def col(t, name, dtype="varchar", length=50, nullable=True, **kw):
    return ColumnInfo("dbo", t, name, dtype, length, 0, 0, nullable, **kw)


def catalog():
    cat = SchemaCatalog()
    acc = TableInfo("dbo", "Accounts", primary_key=["AccountNumber"], unique_sets=[["AccountNumber"]], row_count=10)
    acc.columns = {"accountnumber": col("Accounts", "AccountNumber", nullable=False), "ssn": col("Accounts", "SSN")}
    txn = TableInfo("dbo", "Txn", primary_key=["Id"], unique_sets=[["Id"]], row_count=100)
    txn.columns = {"id": col("Txn", "Id", "int", 4, False), "accountnumber": col("Txn", "AccountNumber", nullable=False),
                   "email": col("Txn", "Email")}
    cat.add_table(acc)
    cat.add_table(txn)
    cat.foreign_keys = [ForeignKey("FK_Txn_Acc", "dbo", "Txn", "dbo", "Accounts", [("AccountNumber", "AccountNumber")])]
    return cat


def rules(tables):
    return parse_rules({"tables": tables})


def test_fk_child_auto_included_and_strategies():
    r = rules([{"table": "Accounts", "columns": [{"name": "AccountNumber", "type": "account_number"}]}])
    plan = build_plan(catalog(), r, EX, True)
    assert plan.ok, plan.errors
    by = {t.info.name: t for t in plan.tables}
    assert by["Txn"].columns[0].auto_added and by["Txn"].columns[0].domain.name == "account_number"
    assert by["Accounts"].strategy == "single"   # key is masked
    assert by["Txn"].strategy == "chunked"       # int key, not masked
    assert plan.foreign_keys[0].name == "FK_Txn_Acc"


def test_fk_without_auto_include_is_error():
    r = rules([{"table": "Accounts", "columns": [{"name": "AccountNumber", "type": "account_number"}]}])
    plan = build_plan(catalog(), r, {"auto_include_fk_columns": False}, True)
    assert not plan.ok and "not masked" in plan.errors[0]


def test_fk_domain_mismatch_is_error():
    r = rules([
        {"table": "Accounts", "columns": [{"name": "AccountNumber", "type": "account_number"}]},
        {"table": "Txn", "columns": [{"name": "AccountNumber", "type": "fpe"}]},
    ])
    plan = build_plan(catalog(), r, EX, True)
    assert any("same domain" in e for e in plan.errors)


def test_non_injective_on_unique_column_rejected():
    r = rules([{"table": "Accounts", "columns": [{"name": "AccountNumber", "type": "last_name"}]}])
    plan = build_plan(catalog(), r, {"auto_include_fk_columns": True}, True)
    assert any("not collision-free" in e for e in plan.errors)


def test_cascade_rejected():
    cat = catalog()
    cat.foreign_keys[0].update_action = 1
    r = rules([{"table": "Accounts", "columns": [{"name": "AccountNumber", "type": "account_number"}]}])
    assert any("CASCADE" in e for e in build_plan(cat, r, EX, True).errors)


def test_missing_objects_reported():
    r = rules([
        {"table": "Nope", "columns": [{"name": "A", "type": "email"}]},
        {"table": "Txn", "columns": [{"name": "Zzz", "type": "email"}]},
    ])
    errors = build_plan(catalog(), r, EX, True).errors
    assert any("Table dbo.Nope does not exist" in e for e in errors)
    assert any("Column dbo.Txn.Zzz does not exist" in e for e in errors)


def test_sql_builders():
    r = rules([{"table": "Txn", "columns": [{"name": "Email", "type": "email"}]}])
    tp = build_plan(catalog(), r, EX, True).tables[0]
    sql = update_sql(tp, ranged=True, lower_bound=True)
    assert "UPDATE t SET [Email] = CASE WHEN m1.h IS NULL" in sql
    assert "HASHBYTES('SHA2_256', CAST(t.[Email] AS NVARCHAR(MAX)))" in sql
    assert sql.endswith("t.[Id] > ? AND t.[Id] <= ?")
    assert "GROUP BY HASHBYTES" in distinct_values_sql(tp, tp.columns[0])


def test_check_fits():
    assert check_fits(col("T", "a", "varchar", 5), "abcdef")
    assert check_fits(col("T", "a", "nvarchar", 10), "abcde") is None
    assert check_fits(col("T", "a", "tinyint", 1), "300")
    assert check_fits(col("T", "a", "varchar", 5, nullable=False), None)
    assert check_fits(ColumnInfo("dbo", "T", "d", "decimal", 9, 5, 2, True), "123.45") is None
    assert check_fits(ColumnInfo("dbo", "T", "d", "decimal", 9, 5, 2, True), "1234.5")
