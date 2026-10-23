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
    assert r.domains["acct"].params == {"preserve_last": 4}
