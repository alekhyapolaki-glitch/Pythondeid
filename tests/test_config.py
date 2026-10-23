import pytest

from deid.config import ConfigError, load_rules, load_settings, parse_rules, rules_from_csv


def test_sample_files_load():
    s = load_settings("config/settings.yaml")
    r = load_rules("config/deid_rules.yaml")
    assert s.database["database"]
    assert {"email", "ssn", "account_number"} <= set(r.domains)
    assert r.content_hash


def test_inline_type_and_conflict():
    r = parse_rules({"tables": [{"table": "T", "columns": [{"name": "A", "type": "email"}]}]})
    assert r.tables[0].columns[0].domain == "email"
    with pytest.raises(ConfigError):
        parse_rules({
            "domains": {"email": {"type": "email"}},
            "tables": [{"table": "T", "columns": [{"name": "A", "type": "email", "params": {"token_length": 20}}]}],
        })


def test_unknown_domain_as_type_and_errors():
    r = parse_rules({"tables": [{"table": "T", "columns": [{"name": "A", "domain": "ssn"}]}]})
    assert r.domains["ssn"].type == "ssn"
    with pytest.raises(ConfigError):
        parse_rules({"tables": [{"table": "T", "columns": [{"name": "A", "domain": "nope"}]}]})


def test_csv_import(tmp_path):
    p = tmp_path / "x.csv"
    p.write_text(
        "schema,table,column,mask_type,domain,params_json\n"
        "dbo,A,Email,email,,\n"
        "dbo,A,Other,,,\n"
        'dbo,B,Acct,account_number,acct,"{""preserve_last"": 4}"\n',
        encoding="utf-8",
    )
    r = rules_from_csv(str(p))
    assert [t.table for t in r.tables] == ["A", "B"]
    assert r.domains["acct"].explicit_params() == {"preserve_last": 4}


# ----------------------------------------------------------------- masking policy
from deid.config import update_policy_in_file  # noqa: E402

BASE = {"domains": {"ssn": {"type": "ssn"}, "acct": {"type": "account_number"},
                    "fixed": {"type": "account_number", "params": {"mode": "full"}},
                    "names": {"type": "account_name"}},
        "tables": [{"table": "T", "columns": [{"name": "S", "domain": "ssn"}, {"name": "A", "domain": "acct"},
                                               {"name": "F", "domain": "fixed"}, {"name": "N", "domain": "names"}]}]}


def test_policy_applies_to_domains_without_explicit_setting():
    r = parse_rules(dict(BASE, policy={"ssn": "last4", "account_number": "last4", "names": "hash"}))
    assert r.domains["ssn"].params["mode"] == "last4"
    assert r.domains["acct"].params["mode"] == "last4"
    assert r.domains["fixed"].params["mode"] == "full"          # explicit beats policy
    assert r.domains["names"].params["method"] == "hash"
    assert "mode" not in r.to_dict()["domains"]["acct"].get("params", {})  # not written back as explicit


def test_policy_defaults_validation_and_hash():
    default = parse_rules(BASE)
    assert default.policy["ssn"] == "full" and default.policy["zip"] == "truncate"
    assert default.domains["ssn"].params["mode"] == "full"
    changed = parse_rules(dict(BASE, policy={"ssn": "last4"}))
    assert changed.content_hash != default.content_hash  # masks differ, so the rules fingerprint must too
    with pytest.raises(ConfigError, match="policy.ssn"):
        parse_rules(dict(BASE, policy={"ssn": "first6_last4"}))
    with pytest.raises(ConfigError, match="unknown policy"):
        parse_rules(dict(BASE, policy={"country": "full"}))


def test_update_policy_in_file_keeps_comments(tmp_path):
    p = tmp_path / "rules.yaml"
    p.write_text("# my rules\nalgorithm_version: 1\n\ndomains:\n  ssn: {type: ssn}   # keep me\n"
                 "tables:\n  - table: T\n    columns: [{name: S, domain: ssn}]\n", encoding="utf-8")
    from deid.config import DEFAULT_POLICY
    update_policy_in_file(str(p), dict(DEFAULT_POLICY, ssn="last4", names="hash"))
    update_policy_in_file(str(p), dict(DEFAULT_POLICY, account_number="last4", names="hash"))
    text = p.read_text(encoding="utf-8")
    assert text.count("policy:") == 1 and "# keep me" in text and "# my rules" in text
    r = load_rules(str(p))
    assert r.policy["account_number"] == "last4" and r.domains["ssn"].params["mode"] == "full"


def test_sample_rules_policy_section():
    r = load_rules("config/deid_rules.yaml")
    assert set(r.policy) == {"ssn", "account_number", "credit_card", "names", "phone", "address", "city", "zip"}
