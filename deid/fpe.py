"""Keyed format-preserving encryption (FPE) primitives.

A balanced Feistel network (modelled on NIST FF1) over an arbitrary radix.
For a fixed key, tweak, radix and length the mapping is a *bijection*, so two
different inputs can never produce the same output.  That property is what lets
masked primary keys, account numbers, SSNs, etc. stay unique and keep joining
across tables.

This is used for masking, not for confidentiality of data at rest; nothing here
is ever decrypted in production (``decrypt`` exists for tests and verification).
"""

from __future__ import annotations

import hashlib
import hmac
from functools import lru_cache
from typing import List, Sequence

DIGITS = "0123456789"
LETTERS = "abcdefghijklmnopqrstuvwxyz"


class FeistelCipher:
    def __init__(self, key: bytes, rounds: int = 10):
        if not key:
            raise ValueError("FPE key must not be empty")
        if rounds < 8 or rounds % 2:
            raise ValueError("rounds must be an even number >= 8")
        self._key = key
        self._rounds = rounds

    # ------------------------------------------------------------------ helpers
    def _prf(self, message: bytes, modulus: int) -> int:
        """HMAC-SHA256 based PRF, extended with a counter to cover large moduli."""
        needed = (modulus.bit_length() + 7) // 8 + 8
        if needed <= 32:  # common case (up to ~57 digits): a single block
            return int.from_bytes(hmac.digest(self._key, b"\x00\x00\x00\x00" + message, "sha256")[:needed],
                                  "big") % modulus
        out = b""
        counter = 0
        while len(out) < needed:
            out += hmac.digest(self._key, counter.to_bytes(4, "big") + message, "sha256")
            counter += 1
        return int.from_bytes(out[:needed], "big") % modulus

    def _round_value(self, tweak: bytes, rnd: int, n: int, radix: int, b_len: int, b_val: int, modulus: int) -> int:
        return self._prf(b"%b|%d|%d|%d|%d|%d" % (tweak, rnd, n, radix, b_len, b_val), modulus)

    @staticmethod
    def _num(symbols: Sequence[int], radix: int) -> int:
        value = 0
        for s in symbols:
            value = value * radix + s
        return value

    @staticmethod
    def _symbols(value: int, radix: int, length: int) -> List[int]:
        out = [0] * length
        for i in range(length - 1, -1, -1):
            value, out[i] = divmod(value, radix)
        return out

    def _single_perm(self, tweak: bytes, radix: int) -> List[int]:
        return _permutation(self._key, tweak, radix)

    # ------------------------------------------------------------------ public
    def encrypt(self, symbols: Sequence[int], radix: int, tweak: bytes = b"") -> List[int]:
        self._check(symbols, radix)
        n = len(symbols)
        if n == 0:
            return []
        if n == 1:
            return [self._single_perm(tweak, radix)[symbols[0]]]
        u = n // 2
        v = n - u
        a = self._num(symbols[:u], radix)
        b = self._num(symbols[u:], radix)
        a_len, b_len = u, v
        for i in range(self._rounds):
            m = u if i % 2 == 0 else v
            modulus = radix ** m
            c = (a + self._round_value(tweak, i, n, radix, b_len, b, modulus)) % modulus
            a, a_len = b, b_len
            b, b_len = c, m
        return self._symbols(a, radix, a_len) + self._symbols(b, radix, b_len)

    def decrypt(self, symbols: Sequence[int], radix: int, tweak: bytes = b"") -> List[int]:
        self._check(symbols, radix)
        n = len(symbols)
        if n == 0:
            return []
        if n == 1:
            return [self._single_perm(tweak, radix).index(symbols[0])]
        u = n // 2
        v = n - u
        a = self._num(symbols[:u], radix)
        b = self._num(symbols[u:], radix)
        a_len, b_len = u, v
        for i in range(self._rounds - 1, -1, -1):
            m = u if i % 2 == 0 else v
            modulus = radix ** m
            # forward round was: a' = b, b' = (a + F(b)) mod radix^m
            prev_b, prev_b_len = a, a_len
            prev_a = (b - self._round_value(tweak, i, n, radix, prev_b_len, prev_b, modulus)) % modulus
            a, a_len = prev_a, m
            b, b_len = prev_b, prev_b_len
        return self._symbols(a, radix, a_len) + self._symbols(b, radix, b_len)

    @staticmethod
    def _check(symbols: Sequence[int], radix: int) -> None:
        if radix < 2:
            raise ValueError("radix must be >= 2")
        for s in symbols:
            if not 0 <= s < radix:
                raise ValueError("symbol out of range for radix")

    # ------------------------------------------------------------------ strings
    def encrypt_digits(self, digits: str, tweak: bytes = b"") -> str:
        return "".join(DIGITS[s] for s in self.encrypt([int(c) for c in digits], 10, tweak))

    def decrypt_digits(self, digits: str, tweak: bytes = b"") -> str:
        return "".join(DIGITS[s] for s in self.decrypt([int(c) for c in digits], 10, tweak))


@lru_cache(maxsize=256)
def _permutation(key: bytes, tweak: bytes, radix: int) -> List[int]:
    """Keyed permutation of range(radix), used for single-symbol inputs."""
    order = sorted(
        range(radix),
        key=lambda s: hmac.new(key, b"perm|" + tweak + b"|" + str(s).encode(), hashlib.sha256).digest(),
    )
    perm = [0] * radix
    for src, dst in zip(range(radix), order):
        perm[src] = dst
    return perm


def _char_class(ch: str, digits: bool, letters: bool) -> str:
    if digits and "0" <= ch <= "9":
        return "d"
    if letters and ("a" <= ch <= "z" or "A" <= ch <= "Z"):
        return "l"
    return ""


def encrypt_text(
    cipher: FeistelCipher,
    text: str,
    tweak: bytes,
    preserve_first: int = 0,
    preserve_last: int = 0,
    digits: bool = True,
    letters: bool = True,
) -> str:
    """Format-preserving encryption of the ASCII letters/digits inside ``text``.

    * separators, spaces, punctuation and non-ASCII characters stay where they are
    * digits stay digits, letters stay letters and keep their upper/lower case
    * the first ``preserve_first`` / last ``preserve_last`` alphanumerics are kept
      (e.g. keep the last 4 of an account number); the kept characters are bound
      into the tweak so the overall mapping remains a bijection.
    """
    chars = list(text)
    positions = [i for i, ch in enumerate(chars) if _char_class(ch, digits, letters)]
    if preserve_first + preserve_last >= len(positions):
        return text
    kept_idx = positions[:preserve_first] + positions[len(positions) - preserve_last:]
    work = positions[preserve_first:len(positions) - preserve_last]
    kept = "".join(chars[i] for i in kept_idx).lower()
    base_tweak = tweak + b"|pf" + str(preserve_first).encode() + b"|pl" + str(preserve_last).encode() + b"|" + kept.encode()

    for cls in ("d", "l"):
        idx = [i for i in work if _char_class(chars[i], digits, letters) == cls]
        if not idx:
            continue
        if cls == "d":
            out = cipher.encrypt([ord(chars[i]) - 48 for i in idx], 10, base_tweak + b"|d")
            for i, s in zip(idx, out):
                chars[i] = DIGITS[s]
        else:
            out = cipher.encrypt([ord(chars[i].lower()) - 97 for i in idx], 26, base_tweak + b"|l")
            for i, s in zip(idx, out):
                new = LETTERS[s]
                chars[i] = new.upper() if chars[i].isupper() else new
    return "".join(chars)
