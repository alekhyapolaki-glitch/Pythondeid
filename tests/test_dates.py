"""Dates stay dates, in their original format: text layouts, Excel date cells and SQL date columns."""

import datetime as dt
import re

import pytest

from deid.masking import MaskerError, create_masker
from deid.masking.dates import parse_date_text

LAYOUTS = [
    "1980-04-12", "1980/04/12", "1980.04.12", "1980-4-12", "19800412", "04/12/1980", "4/2/1980", "04-12-1980",
    "04.12.1980", "12-Apr-1980", "12 Apr 1980", "12-APRIL-1980", "Apr 12 1980", "April 12, 1980", "apr. 2, 1980",
    "1980-04-12T10:15:00.123", "1980-04-12 10:15:00", "04/12/1980 10:15 AM", "2024-01-05 08:00:00.0000000 +05:30",
    "  1980-04-12  ",
]


def _shape(text):
    """Layout fingerprint: digits -> 9, letters -> a/A (case kept), other characters as they are."""
    return re.sub(r"[a-z]", "a", re.sub(r"[A-Z]", "A", re.sub(r"\d", "9", text)))


@pytest.mark.parametrize("value", LAYOUTS)
def test_layout_is_preserved(keyring, value):
    out = create_masker("date_shift", "d", keyring, {"max_days": 20}).mask(value)
    parse_date_text(out)                       # still a valid date
    assert out != value
    if not re.search(r"[A-Za-z]{3}", value) and "/" not in value.split()[0][:5] and not re.match(r"\d/", value):
        assert _shape(out) == _shape(value)    # same digits/separators layout (fixed-width layouts)
    assert out[len(out) - len(out.lstrip()):] == out.lstrip()  # leading spaces kept
    assert out.endswith(value[len(value.rstrip()):])            # trailing spaces / time / zone kept


def test_padding_and_month_names_follow_the_input(keyring):
    m = create_masker("date_shift", "d", keyring, {"max_days": 20})
    assert re.fullmatch(r"\d{1,2}/\d{1,2}/\d{4}", m.mask("4/2/1980"))
    assert re.fullmatch(r"\d{2} [A-Z]{3,9} \d{4}", m.mask("12 APRIL 1980"))
    assert re.fullmatch(r"[a-z]{3}\. \d{1,2}, \d{4}", m.mask("apr. 2, 1980"))
    assert m.mask("04/12/1980 10:15 AM").endswith(" 10:15 AM")


def test_same_date_same_shift_in_every_layout(keyring):
    m = create_masker("date_shift", "d", keyring)
    shifted = {parse_date_text(m.mask(v))[0] for v in ("1980-04-12", "04/12/1980", "12-Apr-1980", "April 12, 1980",
                                                         "19800412", "1980/4/12")}
    assert len(shifted) == 1


def test_day_first_and_generalization(keyring):
    dmy = create_masker("date_shift", "d", keyring, {"day_first": True})
    mdy = create_masker("date_shift", "d", keyring)
    assert parse_date_text(dmy.mask("12/04/1980"), day_first=True)[0] == parse_date_text(mdy.mask("04/12/1980"))[0]
    year = create_masker("date_shift", "d", keyring, {"generalize": "year"})
    assert year.mask("04/12/1980") == "01/01/1980" and year.mask("April 12, 1980") == "January 01, 1980"
    with pytest.raises(MaskerError):
        mdy.mask("13/45/1980")
    with pytest.raises(MaskerError):
        mdy.mask("12 Foo 1980")


@pytest.mark.parametrize("mode", ["in_place", "streaming"])
def test_excel_date_cells_stay_dates_with_their_format(tmp_path, keyring, mode):
    openpyxl = pytest.importorskip("openpyxl")
    from deid.config import parse_rules
    from deid.files import FileDeidentifier, find_inputs, parse_file_rules
    rules = parse_rules({"domains": {"d": {"type": "date_shift"}},
                         "tables": [{"table": "T", "columns": [{"name": "X", "domain": "d"}]}]})
    (tmp_path / "in").mkdir()
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.append(["Dob", "Opened", "Text", "Amount"])
    ws.append([dt.date(1980, 4, 12), dt.datetime(2015, 3, 1, 9, 30), "4/2/1980", 1234.5])
    ws["A2"].number_format, ws["B2"].number_format, ws["D2"].number_format = "mm/dd/yyyy", "yyyy-mm-dd hh:mm", "#,##0.00"
    wb.save(tmp_path / "in" / "f.xlsx")
    fr = parse_file_rules({"defaults": {"excel": {"mode": mode, "header_row": 1}}, "files": [{"pattern": "*", "columns": [
        {"name": "Dob", "domain": "d"}, {"name": "Opened", "domain": "d"}, {"name": "Text", "domain": "d"}]}]}, rules)
    p, rule = find_inputs(str(tmp_path / "in"), fr)[0][0]
    FileDeidentifier(rules, fr, keyring).process(p, tmp_path / "in", tmp_path / "out", rule, False, False)
    out = openpyxl.load_workbook(tmp_path / "out" / "f_deid.xlsx").active
    assert out["A2"].is_date and out["A2"].number_format == "mm/dd/yyyy" and out["A2"].value.date() != dt.date(1980, 4, 12)
    assert out["B2"].is_date and out["B2"].number_format == "yyyy-mm-dd hh:mm" and out["B2"].value.time() == dt.time(9, 30)
    assert re.fullmatch(r"\d{1,2}/\d{1,2}/\d{4}", out["C2"].value)
    assert out["D2"].value == 1234.5 and out["D2"].number_format == "#,##0.00"
