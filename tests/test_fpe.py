import itertools

from deid.masking.fpe import FeistelCipher, encrypt_text


def test_bijection_over_full_small_domains():
    c = FeistelCipher(b"k" * 32)
    for n, radix in ((1, 10), (2, 10), (3, 10), (2, 26), (3, 7)):
        domain = list(itertools.product(range(radix), repeat=n))
        out = {tuple(c.encrypt(list(x), radix, b"t")) for x in domain}
        assert len(out) == len(domain), (n, radix)


def test_roundtrip_and_determinism():
    c = FeistelCipher(b"secret-key-for-tests")
    for digits in ("0", "12", "123456789", "4111111111111111", "9" * 40):
        enc = c.encrypt_digits(digits, b"x")
        assert enc == c.encrypt_digits(digits, b"x")
        assert len(enc) == len(digits) and enc.isdigit()
        assert c.decrypt_digits(enc, b"x") == digits


def test_tweak_and_key_change_output():
    a = FeistelCipher(b"key-a-key-a-key-a")
    b = FeistelCipher(b"key-b-key-b-key-b")
    v = "123456789012"
    assert a.encrypt_digits(v, b"1") != a.encrypt_digits(v, b"2")
    assert a.encrypt_digits(v, b"1") != b.encrypt_digits(v, b"1")


def test_encrypt_text_preserves_format_and_case():
    c = FeistelCipher(b"k" * 32)
    out = encrypt_text(c, "AbC-1234-xy", b"t")
    assert len(out) == 11 and out[3] == "-" and out[8] == "-"
    assert out[0].isupper() and out[1].islower() and out[2].isupper()
    assert out[4:8].isdigit()


def test_encrypt_text_preserve_last():
    c = FeistelCipher(b"k" * 32)
    out = encrypt_text(c, "1234-5678-9012", b"t", preserve_last=4)
    assert out.endswith("9012") and out != "1234-5678-9012"


def test_encrypt_text_bijective_with_preserve():
    c = FeistelCipher(b"k" * 32)
    vals = ["%04d" % i for i in range(10000)]
    assert len({encrypt_text(c, v, b"t", preserve_first=1) for v in vals}) == 10000
