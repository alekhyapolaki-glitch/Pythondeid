"""Profiles (internal/external), HIPAA Safe Harbor helpers and the refresh command's exit codes."""

import pytest

from deid.cli.refresh_command import EXIT_CODES
from deid.config import ConfigError, load_profile, load_rules, parse_rules
from deid.masking import MaskerError, create_masker

PROFILES = "config/profiles"


def test_shipped_profiles_load_and_differ():
    internal, external = load_profile("internal", PROFILES), load_profile("external", PROFILES)
    assert internal.policy["dates"] == "shift" and internal.policy["free_text"] == "scrub"
    assert external.policy["dates"] == "year" and external.policy["free_text"] == "redact"
    assert external.policy["zip"] == "hipaa"
    assert internal.policy["credit_card"] == external.policy["credit_card"] == "full"


def test_profile_overrides_rules_policy_and_changes_hash():
    base = load_rules("config/deid_rules.yaml")
    ext = load_rules("config/deid_rules.yaml", load_profile("external", PROFILES))
    assert ext.profile == "external" and base.profile == ""
    assert ext.domains["person_dates"].params["generalize"] == "year"
    assert base.domains["person_dates"].params["generalize"] == "none"   # "shift"
    assert ext.domains["notes"].params["mode"] == "redact"
    assert ext.domains["zip"].params["mode"] == "hipaa"
    assert ext.content_hash != base.content_hash   # a dry-run of one profile never unlocks a run of another


def test_profile_validation(tmp_path):
    (tmp_path / "bad.yaml").write_text("policy: {ssn: partial}\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="policy.ssn"):
        load_profile("bad", str(tmp_path))
    with pytest.raises(ConfigError, match="not found"):
        load_profile("nope", str(tmp_path))
    with pytest.raises(ConfigError, match="Invalid profile name"):
        load_profile("../etc", str(tmp_path))


def test_hipaa_zip(keyring):
    z = create_masker("zip", "zip", keyring, {"mode": "hipaa"})
    assert z.mask("02118") == "02100" and z.mask("80202-1234") == "80200-0000"
    for restricted in ("03601", "89301", "823-44"):
        assert set(c for c in z.mask(restricted) if c.isdigit()) == {"0"}


def test_birth_date_year_and_age_90_grouping(keyring):
    dob = create_masker("date_shift", "d", keyring, {"generalize": "year", "birth_date": True, "reference_year": 2026})
    assert dob.mask("1980-04-12") == "1980-01-01"
    assert dob.mask("1930-06-01") == "1936-01-01" == dob.mask("1901-01-01")   # 90 or older -> one group
    other = create_masker("date_shift", "d", keyring, {"generalize": "year", "reference_year": 2026})
    assert other.mask("1930-06-01") == "1930-01-01"   # only birth dates are grouped
    with pytest.raises(MaskerError):
        create_masker("date_shift", "d", keyring, {"birth_date": "yes"})


def test_birth_date_is_a_column_setting_sharing_the_persons_offset(keyring):
    from deid.masking import build_maskers, column_masker
    r = parse_rules({"domains": {"pd": {"type": "date_shift", "params": {"shift_by": "entity"}}},
                     "tables": [{"table": "T", "columns": [
                         {"name": "Dob", "domain": "pd", "entity_column": "Id", "birth_date": True},
                         {"name": "Visit", "domain": "pd", "entity_column": "Id"}]}]})
    base = build_maskers(r.domains.values(), keyring)["pd"]
    dob = column_masker(base, keyring, {"birth_date": True})
    # internal profile (shift): same per-person offset for the birth date and the visit -> age preserved
    import datetime as dt
    d1, d2 = dob.mask("1980-04-12", "7"), base.mask("2024-01-05", "7")
    assert (dt.date.fromisoformat(d2) - dt.date.fromisoformat(d1)).days == (dt.date(2024, 1, 5) - dt.date(1980, 4, 12)).days


def test_exit_codes_are_distinct_and_documented():
    assert len(set(EXIT_CODES.values())) == len(EXIT_CODES)
    assert EXIT_CODES["SUCCEEDED"] == 0
    import deid.cli.refresh_command as rc
    for status, code in EXIT_CODES.items():
        assert "%d  %s" % (code, status) in rc.__doc__ or "%d %s" % (code, status) in rc.__doc__
