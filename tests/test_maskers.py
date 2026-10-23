import pytest

from deid.maskers import CreditCardMasker, KeyRing, MaskerError, SsnMasker, create_masker


def test_same_domain_same_output_across_instances(keyring):
    a = create_masker("email", "email", keyring)
    b = create_masker("email", "email", keyring)
    assert a.mask("John.Doe@Mail.com") == b.mask("john.doe@mail.com ")


def test_different_domains_differ(keyring):
    a = create_masker("account_number", "acct_a", keyring)
    b = create_masker("account_number", "acct_b", keyring)
    assert a.mask("ACC-000123-01") != b.mask("ACC-000123-01")


def test_email_shape(keyring):
    m = create_masker("email", "email", keyring, {"domain": "test.local", "token_length": 10})
    out = m.mask("someone@company.com")
    local, domain = out.split("@")
    assert domain == "test.local" and local.startswith("user") and len(local) == 14
    assert m.mask(None) is None and m.mask("") == ""


def test_email_preserve_domain(keyring):
    m = create_masker("email", "email", keyring, {"preserve_domain": True})
    assert m.mask("a@Corp.ORG").endswith("@corp.org")


def test_ssn_formats_consistent(keyring):
    m = create_masker("ssn", "ssn", keyring)
    dashed = m.mask("123-45-6789")
    plain = m.mask("123456789")
    assert dashed.replace("-", "") == plain
    assert len(dashed) == 11 and dashed[3] == "-" and dashed[6] == "-"
    assert SsnMasker._valid(plain)
    assert plain != "123456789"


def test_ssn_zero_pad_for_int_columns(keyring):
    m = create_masker("ssn", "ssn", keyring)
    assert m.mask("12345678") == m.mask("012345678")


def test_ssn_bijective_sample(keyring):
    m = create_masker("ssn", "ssn", keyring, {"output_format": "digits"})
    vals = ["%09d" % (100000000 + i * 7919) for i in range(5000)]
    assert len({m.mask(v) for v in vals}) == len(vals)


def test_credit_card_luhn_and_bin(keyring):
    m = create_masker("credit_card", "card", keyring, {"preserve_first": 6})
    for pan in ("4111111111111111", "5500000000000004", "340000000000009"):
        out = m.mask(pan)
        assert len(out) == len(pan) and out[:6] == pan[:6] and out != pan
        assert CreditCardMasker.luhn_valid(out)
    assert m.mask("4111-1111-1111-1111").count("-") == 3


def test_credit_card_preserve_last4(keyring):
    m = create_masker("credit_card", "card", keyring, {"preserve_last": 4})
    assert m.mask("4111111111111111").endswith("1111")


def test_account_number_format(keyring):
    m = create_masker("account_number", "acct", keyring, {"preserve_last": 2})
    out = m.mask("ACC-000123-01")
    assert len(out) == 13 and out[3] == "-" and out[10] == "-" and out.endswith("01")


def test_phone_keeps_punctuation(keyring):
    m = create_masker("phone", "phone", keyring)
    out = m.mask("(555) 123-4567")
    assert out[0] == "(" and out[4:6] == ") " and out[9] == "-"


def test_names_case_and_determinism(keyring):
    m = create_masker("first_name", "first_name", keyring)
    assert m.mask("MARIA").isupper()
    assert m.mask("maria").lower() == m.mask("Maria").lower()
    full = create_masker("full_name", "full_name", keyring)
    assert len(full.mask("John Q Public").split()) == 3
    assert "," in full.mask("Public, John")


def test_zip_truncate(keyring):
    m = create_masker("zip", "zip", keyring)
    assert m.mask("80202-1234") == "80200-0000"


def test_date_shift(keyring):
    m = create_masker("date_shift", "dob", keyring, {"max_days": 30})
    out = m.mask("1980-04-12")
    assert out != "1980-04-12" and len(out) == 10
    assert m.mask("1980-04-12T10:15:00.000").startswith(out)
    assert create_masker("date_shift", "d", keyring, {"generalize": "year"}).mask("1980-04-12") == "1980-01-01"
    with pytest.raises(MaskerError):
        m.mask("not a date")


def test_redact_nullify_hash(keyring):
    assert create_masker("redact", "r", keyring).mask("secret") == "REDACTED"
    assert create_masker("redact", "r", keyring, {"preserve_length": True}).mask("ab cd") == "XX XX"
    assert create_masker("nullify", "n", keyring).mask("x") is None
    h = create_masker("hash", "h", keyring, {"length": 16})
    assert len(h.mask("abc")) == 16 and h.mask("abc") == h.mask("abc")


def test_param_validation(keyring):
    with pytest.raises(MaskerError):
        create_masker("email", "e", keyring, {"bogus": 1})
    with pytest.raises(MaskerError):
        create_masker("unknown_type", "x", keyring)


def test_key_requirements():
    with pytest.raises(MaskerError):
        KeyRing.from_string("short")
    assert len(KeyRing.generate()) >= 32
