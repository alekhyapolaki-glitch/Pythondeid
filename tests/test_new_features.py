"""Tests for: last-4 modes, type-independent normalisation, per-person date shifting, free text,
column-level format overrides, type expectations, batch sizing and parallel masking."""

import pytest

from deid.advisor import recommend_batch_size, required_output_chars
from deid.config import ConfigError, parse_rules
from deid.engine import build_plan, distinct_values_sql, update_sql
from deid.maskers import MaskerError, build_maskers, column_masker, create_masker
from deid.parallel import MaskingPool, mask_rows
from deid.schema import ColumnInfo, IndexInfo, SchemaCatalog, TableInfo, parse_type, same_type


# ----------------------------------------------------------------- last-4 modes
def test_ssn_last4(keyring):
    m = create_masker("ssn", "ssn", keyring, {"mode": "last4"})
    out = m.mask("123-45-6789")
    assert out.endswith("6789") and out != "123-45-6789" and out[3] == "-"
    assert m.mask("123456789") == out.replace("-", "")
    vals = ["%05d6789" % i for i in range(10000, 30000)]
    assert len({m.mask(v) for v in vals}) == len(vals)  # still collision-free


def test_ssn_full_vs_last4_differ(keyring):
    full = create_masker("ssn", "ssn", keyring)
    assert not full.mask("123-45-6789").endswith("6789")


def test_account_modes(keyring):
    full = create_masker("account_number", "acct", keyring, {"mode": "full"})
    last4 = create_masker("account_number", "acct", keyring, {"mode": "last4"})
    assert full.mask("ACC-000123-01")[-4:] != "3-01"
    assert last4.mask("ACC-000123-01").endswith("23-01")
    with pytest.raises(MaskerError):
        create_masker("account_number", "a", keyring, {"mode": "last4", "preserve_last": 2})
    with pytest.raises(MaskerError):
        create_masker("account_number", "a", keyring, {"mode": "bogus"})


def test_card_first6_last4(keyring):
    m = create_masker("credit_card", "card", keyring, {"mode": "first6_last4"})
    out = m.mask("4111111111111111")
    assert out[:6] == "411111" and out[-4:] == "1111" and out != "4111111111111111"


# ----------------------------------------------------------------- type-independent consistency
def test_normalize_digits_varchar_and_int_agree(keyring):
    m = create_masker("account_number", "member", keyring, {"normalize": "digits", "pad_to": 12})
    as_varchar = m.mask("000000012345")
    as_int = m.mask("12345")
    assert as_varchar.isdigit() and len(as_varchar) == 12
    assert int(as_varchar) == int(as_int)
    assert m.mask("MBR-000000012345").endswith(as_varchar)


def test_normalize_digits_bijective_and_bounds(keyring):
    m = create_masker("account_number", "member", keyring, {"normalize": "digits", "pad_to": 5})
    assert len({int(m.mask(str(i))) for i in range(20000)}) == 20000
    with pytest.raises(MaskerError):
        m.mask("1234567")
    with pytest.raises(MaskerError):
        create_masker("account_number", "x", keyring, {"normalize": "digits"})  # pad_to required


def test_ssn_int_column_matches_text(keyring):
    m = create_masker("ssn", "ssn", keyring)
    assert int(m.mask("12345678")) == int(m.mask("012-34-5678").replace("-", ""))


# ----------------------------------------------------------------- per-person dates
def test_date_shift_per_entity_keeps_intervals(keyring):
    m = create_masker("date_shift", "d", keyring, {"shift_by": "entity", "max_days": 90})
    a = m.mask("2024-01-05", "42")
    b = m.mask("2024-01-09T12:30:00", "42")
    import datetime as dt
    da, db = dt.date.fromisoformat(a), dt.date.fromisoformat(b[:10])
    assert (db - da).days == 4 and b.endswith("T12:30:00")
    others = {m.mask("2024-01-05", str(e)) for e in range(50)}
    assert len(others) > 10  # different people get different offsets
    assert m.mask("2024-01-05", " 42 ") == a  # entity normalised
    assert m.mask("2024-01-05", None)  # falls back to per-value shift


def test_entity_required_in_rules():
    with pytest.raises(ConfigError, match="entity_column"):
        parse_rules({"domains": {"d": {"type": "date_shift", "params": {"shift_by": "entity"}}},
                     "tables": [{"table": "T", "columns": [{"name": "Dob", "domain": "d"}]}]})
    with pytest.raises(ConfigError, match="only valid"):
        parse_rules({"tables": [{"table": "T", "columns": [{"name": "Dob", "type": "date_shift",
                                                             "entity_column": "Id"}]}]})


# ----------------------------------------------------------------- free text
def _free_text_maskers(keyring, detectors=None, custom=None):
    from deid.config import DomainRule
    params = {}
    if detectors is not None:
        params["detectors"] = detectors
    if custom is not None:
        params["custom_patterns"] = custom
    domains = [DomainRule("email", "email", {}), DomainRule("ssn", "ssn", {}), DomainRule("notes", "free_text", params)]
    return build_maskers(domains, keyring)


def test_free_text_default_tags(keyring):
    m = _free_text_maskers(keyring)["notes"]
    out = m.mask("Call (555) 123-4567 or a.b@corp.com, SSN 123-45-6789, card 4111 1111 1111 1111, ref 12345678901234")
    assert out == "Call [PHONE] or [EMAIL], SSN [SSN], card [CARD], ref 12345678901234"


def test_free_text_mask_with_domains_matches_columns(keyring):
    ms = _free_text_maskers(keyring, {"email": {"action": "mask", "domain": "email"},
                                      "ssn": {"action": "mask", "domain": "ssn"}, "phone": {"action": "remove"}})
    out = ms["notes"].mask("Mail John.Doe@Mail.com re SSN 123-45-6789 tel 555-123-4567.")
    assert ms["email"].mask("john.doe@mail.com") in out
    assert ms["ssn"].mask("123-45-6789") in out
    assert "555" not in out


def test_free_text_custom_and_modes(keyring):
    ms = _free_text_maskers(keyring, {}, [{"name": "mrn", "regex": r"MRN\d{6}", "action": "tag", "tag": "[MRN]"}])
    assert ms["notes"].mask("see MRN123456 today") == "see [MRN] today"
    assert create_masker("free_text", "n", keyring, {"mode": "redact"}).mask("x") == "[REDACTED]"
    assert create_masker("free_text", "n", keyring, {"mode": "nullify"}).mask("x") is None
    with pytest.raises(MaskerError):
        create_masker("free_text", "n", keyring, {"custom_patterns": [{"name": "bad", "regex": "("}]})


def test_free_text_undefined_domain_reference():
    with pytest.raises(ConfigError, match="not defined"):
        parse_rules({"domains": {"notes": {"type": "free_text", "params": {
            "detectors": {"email": {"action": "mask", "domain": "nope"}}}}},
            "tables": [{"table": "T", "columns": [{"name": "N", "domain": "notes"}]}]})


# ----------------------------------------------------------------- column-level options
def test_output_format_override_keeps_identity(keyring):
    base = create_masker("ssn", "ssn", keyring)
    digits = column_masker(base, keyring, {"output_format": "digits"})
    assert digits.mask("123-45-6789") == base.mask("123-45-6789").replace("-", "")
    with pytest.raises(MaskerError):
        column_masker(base, keyring, {"mode": "last4"})  # identity params cannot vary per column


def test_column_keys_validated():
    r = parse_rules({"tables": [{"table": "T", "columns": [
        {"name": "S", "type": "ssn", "output_format": "digits", "expected_input_type": "char(11)",
         "output_type": "char(9)"}]}]})
    c = r.tables[0].columns[0]
    assert c.overrides == {"output_format": "digits"} and c.output_type == "char(9)"
    with pytest.raises(ConfigError, match="unknown key"):
        parse_rules({"tables": [{"table": "T", "columns": [{"name": "E", "type": "email", "output_format": "x"}]}]})
    with pytest.raises(ConfigError, match="algorithm_version"):
        parse_rules({"algorithm_version": 99, "tables": []})


def test_parse_and_compare_types():
    assert parse_type("nvarchar(20)").max_chars == 20
    assert parse_type("varchar(max)").max_chars == -1
    live = ColumnInfo("dbo", "T", "c", "varchar", 11, 0, 0, True)
    assert same_type("varchar(11)", live) and not same_type("varchar(12)", live) and not same_type("char(11)", live)
    with pytest.raises(ValueError):
        parse_type("varchr(5)")


# ----------------------------------------------------------------- planning
def _catalog():
    cat = SchemaCatalog()
    t = TableInfo("dbo", "P", primary_key=["Id"], unique_sets=[["Id"], ["SSN"]], row_count=2000000,
                  data_bytes=2000000 * 512)
    t.columns = {"id": ColumnInfo("dbo", "P", "Id", "int", 4, 10, 0, False),
                 "ssn": ColumnInfo("dbo", "P", "SSN", "char", 11, 0, 0, True),
                 "dob": ColumnInfo("dbo", "P", "Dob", "date", 3, 0, 0, True)}
    t.unique_indexes = [IndexInfo("PK_P", ["Id"], is_primary_key=True, is_clustered=True),
                        IndexInfo("UX_P_SSN", ["SSN"])]
    cat.add_table(t)
    return cat


BATCHING = {"target_batch_mb": 256, "min_batch_size": 10000, "max_batch_size": 500000}


def test_unique_index_disabled_allows_chunking_and_auto_batch():
    r = parse_rules({"tables": [{"table": "P", "columns": [{"name": "SSN", "type": "ssn"}]}]})
    plan = build_plan(_catalog(), r, {"batch_size": "auto"}, True, BATCHING)
    tp = plan.tables[0]
    assert plan.ok and tp.strategy == "chunked" and [i.name for i in tp.disable_indexes] == ["UX_P_SSN"]
    assert tp.batch_size == 500000  # 256 MB / 512 B = 524k, capped at max
    plan = build_plan(_catalog(), r, {"disable_unique_indexes": False}, True, BATCHING)
    assert plan.tables[0].strategy == "single"


def test_expected_input_type_mismatch():
    r = parse_rules({"tables": [{"table": "P", "columns": [
        {"name": "SSN", "type": "ssn", "expected_input_type": "varchar(11)"}]}]})
    assert any("expected_input_type" in e for e in build_plan(_catalog(), r, {}, True, BATCHING).errors)
    plan = build_plan(_catalog(), r, {"type_mismatch": "warn"}, True, BATCHING)
    assert plan.ok and any("expected_input_type" in w for w in plan.warnings)


def test_entity_sql():
    r = parse_rules({"domains": {"d": {"type": "date_shift", "params": {"shift_by": "entity"}}},
                     "tables": [{"table": "P", "columns": [{"name": "Dob", "domain": "d", "entity_column": "Id"}]}]})
    tp = build_plan(_catalog(), r, {}, True, BATCHING).tables[0]
    assert tp.columns[0].entity_info.name == "Id"
    sql = distinct_values_sql(tp, tp.columns[0])
    assert "CONCAT(ISNULL(N'1' + CAST(t.[Id] AS NVARCHAR(MAX)), N'0')" in sql and "MIN(CAST(t.[Id]" in sql
    assert "CONCAT(ISNULL(N'1' + CAST(t.[Id]" in update_sql(tp, False, False)


def test_batch_size_bounds():
    small = TableInfo("dbo", "S", row_count=5000, data_bytes=5000 * 100)
    wide = TableInfo("dbo", "W", row_count=10 ** 8, data_bytes=10 ** 8 * 20000)
    assert recommend_batch_size(small, BATCHING) == 5000
    assert recommend_batch_size(wide, BATCHING) == 13000  # 256 MB / 20 KB rows


def test_required_output_chars():
    assert required_output_chars("email", {}, 50) == len("user") + 16 + 1 + len("example.com")
    assert required_output_chars("ssn", {"output_format": "dashed"}, 9) == 11
    assert required_output_chars("account_number", {"normalize": "digits", "pad_to": 12}, 8) == 12


# ----------------------------------------------------------------- parallel masking
def test_parallel_equals_in_process(keyring):
    from deid.config import DomainRule
    domains = [DomainRule("email", "email", {}), DomainRule("acct", "account_number", {"mode": "last4"})]
    maskers = build_maskers(domains, keyring)
    rows = [(bytes([i % 256]) * 32, "person%d@corp.com" % i) for i in range(3000)]
    batches = [rows[i:i + 500] for i in range(0, len(rows), 500)]
    pool = MaskingPool(2, domains, keyring)
    try:
        got = [r for _, res in pool.map(maskers["email"], {}, batches, True, parallel=True) for r in res]
    finally:
        pool.close()
    assert got == mask_rows(maskers["email"], rows, True)


# ----------------------------------------------------------------- account names (people + businesses)
def test_account_name_people_and_businesses(keyring):
    m = create_masker("account_name", "account_name", keyring)
    assert m.classify("LAURA H TALKO") == "person"
    assert m.classify("WIDGET DEVELOPMENT INC") == "business"
    assert m.classify("JOHN SMITH REVOCABLE TRUST") == "person_entity"
    biz = m.mask("ACME DEVELOPMENT INC")
    assert biz.endswith(" DEVELOPMENT INC") and not biz.startswith("ACME") and biz.isupper()
    assert m.mask("CARNOW, CONIBEAR & ASSOC, LTD").endswith(" & ASSOC, LTD")
    assert m.mask("Acme Development Inc.").endswith(" Development Inc.")
    trust = m.mask("JOHN SMITH REVOCABLE TRUST")
    assert trust.endswith(" REVOCABLE TRUST") and "JOHN" not in trust and "SMITH" not in trust
    person = m.mask("JOHN A SMITH")
    assert person == create_masker("full_name", "account_name", keyring).mask("JOHN A SMITH")
    assert m.mask("ACME DEVELOPMENT INC") == biz  # deterministic


def test_account_name_options(keyring):
    m = create_masker("account_name", "n", keyring, {"extra_business_words": ["Bancshares"], "keep_numbers": True})
    assert m.classify("FIRST MIDWEST BANCSHARES") == "business"
    assert m.mask("1 FAITH HOLDINGS LLC").startswith("1 ")
    with pytest.raises(MaskerError):
        create_masker("account_name", "n", keyring, {"extra_business_words": "LABS"})


def test_name_methods_pick_existing_algorithms(keyring):
    for mtype in ("full_name", "account_name"):
        h = create_masker(mtype, "names", keyring, {"method": "hash", "hash_prefix": "N-", "hash_length": 12})
        expected = create_masker("hash", "names", keyring, {"length": 12, "prefix": "N-", "case_sensitive": False})
        assert h.mask("ACME DEVELOPMENT INC") == expected.mask("ACME DEVELOPMENT INC")
        assert h.mask("John Smith") == h.mask("JOHN SMITH ") and h.injective
        r = create_masker(mtype, "names", keyring, {"method": "redact", "redact_value": "XXX"})
        assert r.mask("John Smith") == "XXX" and r.mask(None) is None
        assert create_masker(mtype, "names", keyring).mask("JOHN A SMITH") != "JOHN A SMITH"
        with pytest.raises(MaskerError):
            create_masker(mtype, "names", keyring, {"method": "scramble"})


def test_name_method_hash_allowed_on_unique_column():
    from deid.maskers import is_injective
    assert is_injective("account_name", {"method": "hash"})
    assert not is_injective("account_name", {"method": "realistic"})
    assert not is_injective("full_name", {})
