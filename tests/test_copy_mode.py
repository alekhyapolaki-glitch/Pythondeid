"""On-the-fly masking without a database: copy_map.yaml parsing, the copy plan's checks and the copy SQL."""

import copy

import pytest

from deid.config import ConfigError, parse_copy_map, parse_rules
from deid.database.schema import ForeignKey
from deid.engine import build_plan
from deid.engine.copy_plan import build_copy_plan, set_transfer
from deid.engine.copy_sql import UNMAPPED_MESSAGE, copy_insert_sql, copy_select_sql, stream_insert_sql

from .test_engine_plan import EX, catalog, col

RULES = [{"table": "Accounts", "columns": [{"name": "AccountNumber", "type": "account_number"}]},
         {"table": "Txn", "columns": [{"name": "Email", "type": "email"}]}]


def _rules(tables=RULES):
    return parse_rules({"tables": copy.deepcopy(tables)})


def _plan(copy_map=None, target=None, tables=RULES, same_instance=True, source_db="Src", target_db="Tgt"):
    rules = _rules(tables)
    plan = build_plan(catalog(), rules, EX, True, mode="on_the_fly")
    build_copy_plan(plan, parse_copy_map(copy_map or {}, rules), target or catalog(), same_instance=same_instance,
                    source_database=source_db, target_server="srv", target_database=target_db,
                    target_connection="tgt")
    return plan


# --------------------------------------------------------------------------- copy_map.yaml
def test_copy_map_defaults_and_mapping():
    cm = parse_copy_map({"target_connection": "lower", "tables": [
        {"source": "dbo.Txn", "target": "stage.Txn_Masked", "columns": ["Id", "Email"], "column_map": {"Email": "Mail"}}]},
        _rules())
    assert (cm.target_connection, cm.on_existing_rows, cm.transfer) == ("lower", "truncate", "auto")
    m = cm.mapping("dbo", "Txn")
    assert m.target_fqn == "stage.Txn_Masked" and m.target_column("EMAIL") == "Mail" and m.target_column("Id") == "Id"
    assert cm.mapping("dbo", "Accounts").target_fqn == "dbo.Accounts"   # not listed: same name


@pytest.mark.parametrize("raw, message", [
    ({"tables": [{"source": "dbo.Other"}]}, "not in the rules file"),
    ({"tables": [{"source": "Txn"}]}, "schema.table"),
    ({"tables": [{"source": "dbo.Txn"}, {"source": "dbo.Txn"}]}, "listed twice"),
    ({"tables": [{"source": "dbo.Txn", "target": "dbo.X"}, {"source": "dbo.Accounts", "target": "dbo.X"}]}, "both write"),
    ({"tables": [{"source": "dbo.Txn", "column_map": {"a": "x", "b": "X"}}]}, "same target column"),
    ({"tables": [{"source": "dbo.Txn", "columns": "some"}]}, "'all' or a list"),
    ({"on_existing_rows": "append"}, "on_existing_rows"),
    ({"transfer": "fast"}, "transfer"),
    ({"target": "x"}, "unknown key"),
])
def test_copy_map_rejects_bad_config(raw, message):
    with pytest.raises(ConfigError, match=message):
        parse_copy_map(raw, _rules())


# --------------------------------------------------------------------------- planner in copy mode
def test_copy_mode_planner_differences():
    plan = _plan()
    assert plan.ok, plan.errors
    by = {t.info.name: t for t in plan.tables}
    assert by["Accounts"].strategy == "chunked"     # a masked key is fine: it is only read from the source
    assert plan.foreign_keys == []                  # the source FKs are never touched
    assert [f.name for f in plan.copy.foreign_keys] == ["FK_Txn_Acc"]   # the target's are
    assert plan.copy.transfer == "set_based" and by["Txn"].target.db_prefix == "[Tgt]."


def test_fk_partner_not_copied_is_not_added():
    plan = _plan(tables=RULES[:1])
    assert [t.info.name for t in plan.tables] == ["Accounts"]
    assert any("Txn is not copied but has" in e for e in plan.errors)   # its target rows would be orphaned


def test_target_checks():
    target = catalog()
    txn = target.get("dbo", "Txn")
    txn.columns["email"] = col("Txn", "Email", "int", 4)                       # masked: checked by value fit
    txn.columns["region"] = col("Txn", "Region", nullable=False)               # NOT NULL, nothing writes it
    txn.columns["note"] = col("Txn", "Note", nullable=False, has_default=True)  # default: fine
    acc = target.get("dbo", "Accounts")
    acc.columns["ssn"] = col("Accounts", "SSN", "varchar", 5)                  # narrower: warning only
    errors, warnings = " ".join(_plan(target=target).errors), " ".join(_plan(target=target).warnings)
    assert "Txn.Region is NOT NULL without a default" in errors and "Note" not in errors
    assert "narrower" in warnings
    assert _plan(target=target).tables[1].columns[0].target_info.data_type == "int"


def test_same_table_and_missing_target_refused():
    assert any("source table itself" in e for e in _plan(target_db="Src").errors)
    assert not any("source table itself" in e for e in _plan(target_db="Src", same_instance=False).errors)
    empty = catalog()
    del empty.tables[("dbo", "txn")]
    assert any("Target table dbo.Txn" in e and "does not exist" in e for e in _plan(target=empty).errors)


def test_target_that_is_also_a_source_is_refused():
    """Same database: Accounts -> Txn while Txn is copied too would empty Txn before reading it."""
    target = catalog()
    plan = _plan({"tables": [{"source": "dbo.Accounts", "target": "dbo.Txn"},
                             {"source": "dbo.Txn", "target": "dbo.Accounts"}]}, target, target_db="Src")
    assert any("is itself a source table" in e for e in plan.errors)


def test_column_mapping_and_selection():
    target = catalog()
    txn = target.get("dbo", "Txn")
    txn.columns["mail"] = txn.columns.pop("email")
    txn.columns["mail"].name = "Mail"
    plan = _plan({"tables": [{"source": "dbo.Txn", "column_map": {"Email": "Mail"}}]}, target)
    assert plan.ok, plan.errors
    tp = plan.tables[1]
    assert [(c.source.name, c.target.name) for c in tp.target.columns] == [
        ("Id", "Id"), ("AccountNumber", "AccountNumber"), ("Email", "Mail")]
    plan = _plan({"tables": [{"source": "dbo.Txn", "columns": ["Id", "AccountNumber"]}]})
    assert any("Email is masked in the rules but not copied" in w for w in plan.warnings)
    assert [c.name for c in plan.tables[1].columns] == ["AccountNumber"]   # Email dropped; FK partner kept


def test_on_existing_rows_error_and_transfer_rules():
    assert any("not empty" in e for e in _plan({"on_existing_rows": "error"}).errors)
    assert _plan(same_instance=False).copy.transfer == "stream"
    assert any("same SQL Server instance" in e for e in _plan({"transfer": "set_based"}, same_instance=False).errors)
    target = catalog()
    plan = _plan(target=target)
    plan.tables[1].target.columns[0].source.data_type = "sql_variant"
    set_transfer(plan, "stream")
    assert any("cannot be streamed" in e for e in plan.errors)


def test_untouched_target_table_with_no_rows_is_fine():
    target = catalog()
    target.get("dbo", "Txn").row_count = 0
    target.foreign_keys.append(ForeignKey("FK_X", "dbo", "Txn", "dbo", "Accounts", [("Id", "AccountNumber")]))
    assert not any("is not copied" in e for e in _plan(tables=RULES[:1], target=target).errors)


# --------------------------------------------------------------------------- copy SQL
def test_copy_sql_masks_with_failsafe_and_moves_types_exactly():
    plan = _plan()
    tp = {t.info.name: t for t in plan.tables}["Txn"]
    sql = copy_insert_sql(tp, True, True)
    assert sql.startswith("INSERT INTO [Tgt].[dbo].[Txn] WITH (TABLOCK) ([Id], [AccountNumber], [Email]) SELECT t.[Id]")
    assert sql.count(UNMAPPED_MESSAGE) == 2          # one fail-safe per masked column
    assert "WHERE t.[Id] > ? AND t.[Id] <= ?" in sql and "ORDER BY" not in sql
    stream = copy_select_sql(tp, True, False, False)
    assert stream.endswith("ORDER BY t.[Id]")
    assert stream_insert_sql(tp) == "INSERT INTO [dbo].[Txn] WITH (TABLOCK) ([Id], [AccountNumber], [Email]) VALUES (?, ?, ?)"
    tp.target.columns[0].source.data_type = "time"
    assert "CONVERT(NVARCHAR(40), t.[Id], 126)" in copy_select_sql(tp, True, False, False)   # exact 100 ns
    assert "CONVERT(NVARCHAR(40)" not in copy_select_sql(tp, False, False, False)            # same server: as is


def test_identifiers_in_copy_sql_are_quoted():
    target = catalog()
    txn = target.get("dbo", "Txn")
    txn.columns["e]vil"] = txn.columns.pop("email")
    txn.columns["e]vil"].name = "E]vil"
    plan = _plan({"tables": [{"source": "dbo.Txn", "column_map": {"Email": "E]vil"}}]}, target)
    assert "[E]]vil]" in copy_insert_sql(plan.tables[1], False, False)
