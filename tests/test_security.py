"""Regression tests for the security review (see SECURITY.md)."""

import csv

import pytest

from deid.config import parse_rules
from deid.database.connection import DatabaseError, build_connection_string
from deid.database.sql import quote_ident
from deid.files import FileDeidentifier, FileRuleError, find_inputs, parse_file_rules

RULES = parse_rules({"domains": {"email": {"type": "email"}},
                     "tables": [{"table": "T", "columns": [{"name": "E", "domain": "email"}]}]})


def test_quote_ident_escapes_and_rejects_bad_identifiers():
    assert quote_ident("a]b; DROP TABLE x--") == "[a]]b; DROP TABLE x--]"
    for bad in ("", "x" * 129, "a\x00b", None):
        with pytest.raises(ValueError):
            quote_ident(bad)


def test_connection_string_extra_keywords_are_restricted():
    db = {"driver": "ODBC Driver 18 for SQL Server", "server": "s", "database": "d", "auth": "windows"}
    cs = build_connection_string(dict(db, extra={"MultiSubnetFailover": "yes"}))
    assert "MultiSubnetFailover=yes" in cs and "PWD" not in cs
    for key in ("PWD", "Driver", "bad;key", "x=y"):
        with pytest.raises(DatabaseError):
            build_connection_string(dict(db, extra={key: "v"}))
    # values containing separators are brace-quoted, so they cannot add keywords
    assert "DATABASE={d;PWD=x}" in build_connection_string(dict(db, database="d;PWD=x"))


def _rules(**extra):
    return parse_file_rules({"files": [dict({"pattern": "*", "columns": [{"name": "Email", "domain": "email"}]},
                                            **extra)]}, RULES)


def test_missing_column_error_does_not_echo_row_values(tmp_path, keyring):
    (tmp_path / "in").mkdir()
    # no header row: the first line is data, and must not appear in the error
    with open(tmp_path / "in" / "a.csv", "w", newline="") as fh:
        csv.writer(fh).writerows([["123-45-6789", "secret@corp.com"], ["1", "x"]])
    fr = _rules()
    p, rule = find_inputs(str(tmp_path / "in"), fr)[0][0]
    with pytest.raises(FileRuleError) as err:
        FileDeidentifier(RULES, fr, keyring).process(p, tmp_path / "in", tmp_path / "out", rule, True, False)
    assert "123-45-6789" not in str(err.value) and "secret@corp.com" not in str(err.value)


def test_max_file_size_guard(tmp_path, keyring):
    (tmp_path / "in").mkdir()
    (tmp_path / "in" / "big.csv").write_bytes(b"Email\n" + b"a@b.com\n" * 200000)  # ~1.6 MB
    fr = _rules(max_file_mb=1)
    p, rule = find_inputs(str(tmp_path / "in"), fr)[0][0]
    with pytest.raises(FileRuleError, match="max_file_mb"):
        FileDeidentifier(RULES, fr, keyring).process(p, tmp_path / "in", tmp_path / "out", rule, True, False)


def test_excel_requires_defusedxml(monkeypatch):
    openpyxl = pytest.importorskip("openpyxl")
    monkeypatch.setattr(openpyxl, "DEFUSEDXML", False, raising=False)
    with pytest.raises(FileRuleError, match="defusedxml"):
        FileDeidentifier._openpyxl()


def test_audit_records_contain_no_values(tmp_path, keyring):
    from deid.audit import AuditTrail
    (tmp_path / "in").mkdir()
    with open(tmp_path / "in" / "a.csv", "w", newline="") as fh:
        csv.writer(fh).writerows([["Email"], ["very.private@corp.com"]])
    fr = _rules()
    p, rule = find_inputs(str(tmp_path / "in"), fr)[0][0]
    res = FileDeidentifier(RULES, fr, keyring).process(p, tmp_path / "in", tmp_path / "out", rule, False, False)
    from dataclasses import asdict
    audit = AuditTrail({"output_dir": str(tmp_path / "audit"), "write_to_db": False}, "run1")
    audit.start_run("files", {})
    audit.file_result(asdict(res))
    audit.end_run("SUCCEEDED")
    for f in (tmp_path / "audit" / "run1").iterdir():
        assert "very.private" not in f.read_text(encoding="utf-8")
