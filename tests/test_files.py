"""CSV / Excel de-identification (deid/files.py)."""

import csv
import datetime as dt

import pytest

openpyxl = pytest.importorskip("openpyxl")

from deid.config import parse_rules  # noqa: E402
from deid.files import FileDeidentifier, FileRuleError, draft_file_rules, find_inputs, parse_file_rules  # noqa: E402
from deid.masking import build_maskers  # noqa: E402

RULES = parse_rules({
    "policy": {"ssn": "full", "names": "realistic"},
    "domains": {
        "email": {"type": "email"}, "ssn": {"type": "ssn"},
        "acct": {"type": "account_number", "params": {"normalize": "digits", "pad_to": 12}},
        "dates": {"type": "date_shift", "params": {"shift_by": "entity"}},
        "names": {"type": "account_name"},
    },
    "tables": [{"table": "T", "columns": [{"name": "E", "domain": "email"}]}],
})


def file_rules(columns, **extra):
    return parse_file_rules({"files": [dict({"name": "f", "pattern": "*", "columns": columns}, **extra)]}, RULES)


def write_csv(path, rows):
    with open(path, "w", newline="", encoding="utf-8") as fh:
        csv.writer(fh).writerows(rows)


def read_csv(path):
    with open(path, newline="", encoding="utf-8-sig") as fh:
        return list(csv.reader(fh))


def run(tmp_path, fr, keyring, **kw):
    deid = FileDeidentifier(RULES, fr, keyring)
    matched, _ = find_inputs(str(tmp_path / "in"), fr)
    return [deid.process(p, tmp_path / "in", tmp_path / "out", r, kw.get("dry_run", False),
                         kw.get("overwrite", False)) for p, r in matched]


def test_csv_masks_like_the_database(tmp_path, keyring):
    (tmp_path / "in").mkdir()
    write_csv(tmp_path / "in" / "c.csv", [["Id", " email ", "SSN", "Dob", "Other"],
                                         ["7", "A.B@X.com", "123-45-6789", "2000-01-02", "keep me"],
                                         ["8", "", "", "", "x"]])
    fr = file_rules([{"name": "Email", "domain": "email"}, {"name": "ssn", "domain": "ssn"},
                     {"name": "DOB", "domain": "dates", "entity_column": "id"}])
    res = run(tmp_path, fr, keyring)[0]
    out = read_csv(tmp_path / "out" / "c_deid.csv")
    db = build_maskers(RULES.domains.values(), keyring)
    assert out[0] == ["Id", " email ", "SSN", "Dob", "Other"]
    assert out[1] == ["7", db["email"].mask("a.b@x.com"), db["ssn"].mask("123-45-6789"),
                      db["dates"].mask("2000-01-02", "7"), "keep me"]
    assert out[2] == ["8", "", "", "", "x"]
    assert res.rows == 2 and res.masked_cells == {"Email": 1, "ssn": 1, "DOB": 1} and res.output_sha256


def test_excel_types_formatting_formulas_and_sheets(tmp_path, keyring):
    (tmp_path / "in").mkdir()
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "Data"
    ws.append(["Acct", "Name", "Opened", "Total"])
    ws["A1"].font = openpyxl.styles.Font(bold=True)
    ws.append([12345, "ACME DEVELOPMENT INC", dt.datetime(2020, 1, 2), 5])
    ws.append(["=1+1", "JOHN A SMITH", dt.datetime(2021, 3, 4), "=D2*2"])
    other = wb.create_sheet("Other")
    other.append(["Acct"])
    other.append(["99"])
    wb.save(tmp_path / "in" / "w.xlsx")
    fr = file_rules([{"name": "Acct", "domain": "acct"}, {"name": "Name", "domain": "names"}], sheets=["data"])
    res = run(tmp_path, fr, keyring)[0]
    out = openpyxl.load_workbook(tmp_path / "out" / "w_deid.xlsx")
    db = build_maskers(RULES.domains.values(), keyring)
    d = out["Data"]
    assert d["A2"].value == int(db["acct"].mask("12345")) and isinstance(d["A2"].value, int)
    assert d["B2"].value.endswith("DEVELOPMENT INC") and d["B2"].value != "ACME DEVELOPMENT INC"
    assert d["A3"].value == "=1+1" and d["D3"].value == "=D2*2"          # formulas untouched
    assert d["C2"].value == dt.datetime(2020, 1, 2) and d["A1"].font.b    # other columns + formatting kept
    assert out["Other"]["A2"].value == "99"                               # sheet not configured
    assert res.formulas_skipped == 1 and res.sheets == ["Data"]


def test_excel_streaming_mode(tmp_path, keyring):
    (tmp_path / "in").mkdir()
    wb = openpyxl.Workbook()
    wb.active.append(["SSN"])
    wb.active.append(["123-45-6789"])
    wb.save(tmp_path / "in" / "s.xlsx")
    fr = file_rules([{"name": "SSN", "domain": "ssn"}], excel={"mode": "streaming", "header_row": 1})
    run(tmp_path, fr, keyring)
    v = openpyxl.load_workbook(tmp_path / "out" / "s_deid.xlsx").active["A2"].value
    assert v == build_maskers(RULES.domains.values(), keyring)["ssn"].mask("123-45-6789")


def test_missing_columns_value_errors_and_safety(tmp_path, keyring):
    (tmp_path / "in").mkdir()
    write_csv(tmp_path / "in" / "a.csv", [["Id", "Dob"], ["1", "not a date"]])
    with pytest.raises(FileRuleError, match="not found"):
        run(tmp_path, file_rules([{"name": "Email", "domain": "email"}]), keyring)
    res = run(tmp_path, file_rules([{"name": "Email", "domain": "email"}], on_missing_column="warn"), keyring)[0]
    assert "not found" in res.message
    with pytest.raises(FileRuleError, match="Unrecognised date"):
        run(tmp_path, file_rules([{"name": "Dob", "domain": "dates", "entity_column": "Id"}]), keyring,
            overwrite=True)
    run(tmp_path, file_rules([{"name": "Dob", "domain": "dates", "entity_column": "Id"}],
                             on_value_error="blank"), keyring, overwrite=True)
    assert read_csv(tmp_path / "out" / "a_deid.csv")[1] == ["1", ""]
    with pytest.raises(FileRuleError, match="already exists"):
        run(tmp_path, file_rules([{"name": "Id", "domain": "ssn"}]), keyring)
    assert not list((tmp_path / "out").glob("*.part"))                   # no partial files left behind
    # output may never replace the input
    fr = file_rules([{"name": "Id", "domain": "ssn"}], output_suffix="")
    deid = FileDeidentifier(RULES, fr, keyring)
    with pytest.raises(FileRuleError, match="overwrite the input"):
        deid.process(tmp_path / "in" / "a.csv", tmp_path / "in", tmp_path / "in", fr.files[0], False, True)


def test_dry_run_writes_nothing(tmp_path, keyring):
    (tmp_path / "in").mkdir()
    write_csv(tmp_path / "in" / "a.csv", [["Email"], ["a@b.com"]])
    res = run(tmp_path, file_rules([{"name": "Email", "domain": "email"}]), keyring, dry_run=True)[0]
    assert res.status == "DRY_RUN" and not (tmp_path / "out").exists()


def test_file_rules_validation():
    with pytest.raises(FileRuleError, match="not defined"):
        file_rules([{"name": "X", "domain": "nope"}])
    with pytest.raises(FileRuleError, match="entity_column"):
        file_rules([{"name": "Dob", "domain": "dates"}])
    with pytest.raises(FileRuleError, match="unknown key"):
        file_rules([{"name": "E", "domain": "email", "output_format": "x"}])
    with pytest.raises(FileRuleError, match="on_value_error"):
        file_rules([{"name": "E", "domain": "email"}], on_value_error="ignore")
    fr = file_rules([{"name": "S", "domain": "ssn", "output_format": "digits"}])
    assert fr.files[0].columns[0].overrides == {"output_format": "digits"}


def test_discover_drafts_valid_rules(tmp_path):
    import yaml
    (tmp_path / "in").mkdir()
    write_csv(tmp_path / "in" / "people.csv", [["Customer Email", "SSN", "Favourite Colour"], ["a@b.c", "1", "red"]])
    write_csv(tmp_path / "in" / "codes.csv", [["Code", "Label"], ["1", "x"]])
    text, n = draft_file_rules(str(tmp_path / "in"), RULES)
    assert n == 2 and '{name: "Customer Email", domain: email}' in text and "# - {name: \"Favourite Colour\"" in text
    fr = parse_file_rules(yaml.safe_load(text), RULES)
    assert [f.name for f in fr.files] == ["people"]                       # codes.csv drafted but commented out
