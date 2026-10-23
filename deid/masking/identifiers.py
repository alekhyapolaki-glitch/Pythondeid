"""Bijective format-preserving maskers for identifiers: generic FPE, account numbers, phones, SSNs, cards."""

from __future__ import annotations

import re

from .base import MODES, BaseMasker, MaskerError, _apply_mode, _choice, _non_negative_int, _reinsert_digits
from .fpe import FeistelCipher, encrypt_text


class FpeMasker(BaseMasker):
    type_name = "fpe"
    description = "Format-preserving encryption of letters/digits (bijective, keeps separators and length)"
    default_params = {
        "preserve_first": 0, "preserve_last": 0, "digits": True, "letters": True,
        "normalize": "none", "pad_to": 0,
    }
    families = ("string", "int", "decimal")
    injective = True

    @classmethod
    def _check_params(cls, p):
        _non_negative_int(p, "preserve_first", "preserve_last", "pad_to")
        if not (p["digits"] or p["letters"]):
            raise MaskerError("At least one of 'digits' or 'letters' must be true")
        _choice(p, "normalize", ("none", "digits"))
        if p["normalize"] == "digits":
            if not 1 <= p["pad_to"] <= 38:
                raise MaskerError(
                    "normalize=digits needs pad_to = the maximum number of digits the identifier can have "
                    "(1-38), e.g. pad_to: 12. This makes '000012345' (varchar) and 12345 (bigint) mask the same.")
            if p["preserve_first"] + p["preserve_last"] >= p["pad_to"]:
                raise MaskerError("preserve_first + preserve_last must be smaller than pad_to")

    def _setup(self):
        self._cipher = FeistelCipher(self._key)

    def canonical(self, value):
        if self.params["normalize"] == "digits":
            digits = re.sub(r"\D", "", value)
            return (digits.lstrip("0") or "0").zfill(self.params["pad_to"]) if digits else value
        return value

    def _mask(self, value):
        p = self.params
        if p["normalize"] == "digits" and re.search(r"\d", value):
            return self._mask_numeric(value)
        return encrypt_text(self._cipher, value, self.type_name.encode(),
                            p["preserve_first"], p["preserve_last"], p["digits"], p["letters"])

    def _mask_numeric(self, value):
        """Type-independent: the digit sequence is treated as a number of fixed width pad_to."""
        p = self.params
        canon = self.canonical(value)
        if len(canon) > p["pad_to"]:
            raise MaskerError("value has %d significant digits but pad_to is %d; raise pad_to" % (
                len(canon.lstrip("0")), p["pad_to"]))
        out = encrypt_text(self._cipher, canon, self.type_name.encode() + b"|num",
                           p["preserve_first"], p["preserve_last"], True, False)
        significant = out.lstrip("0") or "0"
        template_digits = sum(ch.isdigit() for ch in value)
        if p["letters"]:
            value = encrypt_text(self._cipher, value, self.type_name.encode() + b"|alpha", digits=False, letters=True)
        if len(significant) <= template_digits:
            return _reinsert_digits(value, significant.zfill(template_digits))
        return out  # number does not fit the original layout; the engine validates the column length


class AccountNumberMasker(FpeMasker):
    type_name = "account_number"
    description = ("Account/member/policy numbers: FPE keeping format; mode=full (default) or last4; "
                   "normalize=digits for varchar/int consistency")
    default_params = dict(FpeMasker.default_params, mode="full")

    @classmethod
    def _check_params(cls, p):
        _apply_mode(p)
        super()._check_params(p)


PHONE_MODES = ("full", "last4", "area_code")


class PhoneMasker(FpeMasker):
    type_name = "phone"
    description = ("Phone numbers: FPE on digits only, punctuation/format preserved; "
                   "mode=full (default) | last4 | area_code (keep the area code, +1 country code included)")
    default_params = dict(FpeMasker.default_params, letters=False, mode="full")

    @classmethod
    def _check_params(cls, p):
        _choice(p, "mode", PHONE_MODES)
        if p["mode"] != "full" and (p["preserve_first"] or p["preserve_last"]):
            raise MaskerError("phone mode=%s conflicts with preserve_first/preserve_last; set only one" % p["mode"])
        super()._check_params(p)

    def _mask(self, value):
        mode = self.params["mode"]
        if mode == "full":
            return super()._mask(value)
        pf, pl = 0, 0
        if mode == "last4":
            pl = 4
        else:
            digits = re.sub(r"\D", "", value)
            # NANP: 10 digits -> keep 3; 11 digits starting with 1 -> keep "1" + area code
            pf = 4 if (len(digits) == 11 and digits[0] == "1") else (3 if len(digits) >= 10 else 0)
        return encrypt_text(self._cipher, value, b"phone|" + mode.encode(), pf, pl, True, False)


class SsnMasker(BaseMasker):
    type_name = "ssn"
    description = ("US SSN/TIN: bijective FPE on the 9 digits; mode=full (default) or last4; "
                   "realistic=true keeps output inside valid SSA ranges")
    default_params = {"mode": "full", "output_format": "preserve", "realistic": True, "zero_pad": True}
    format_params = frozenset({"output_format"})
    families = ("string", "int", "decimal")
    injective = True

    @classmethod
    def _check_params(cls, p):
        _apply_mode(p)
        _choice(p, "output_format", ("preserve", "dashed", "digits"))

    def _setup(self):
        self._cipher = FeistelCipher(self._key)
        self._keep = 4 if self.params["mode"] == "last4" else 0

    @staticmethod
    def _valid(d: str) -> bool:
        area, group, serial = d[:3], d[3:5], d[5:]
        return area not in ("000", "666") and area[0] != "9" and group != "00" and serial != "0000"

    def canonical(self, value):
        digits = re.sub(r"\D", "", value)
        if self.params["zero_pad"] and value.strip().isdigit() and len(digits) < 9:
            digits = digits.zfill(9)
        return digits if len(digits) == 9 else value

    def _encrypt(self, digits: str) -> str:
        if not self._keep:
            return self._cipher.encrypt_digits(digits, b"ssn")
        kept = digits[-self._keep:]
        return self._cipher.encrypt_digits(digits[:-self._keep], b"ssn|last|" + kept.encode()) + kept

    def _mask(self, value):
        stripped = value.strip()
        digits = self.canonical(value)
        if len(digits) != 9 or not digits.isdigit():
            # Not an SSN shape - still mask it instead of leaking it.
            return encrypt_text(self._cipher, value, b"ssn-nonstandard", 0, self._keep)
        valid = self._valid(digits)
        out = self._encrypt(digits)
        if self.params["realistic"]:
            # Cycle-walking keeps the map a bijection within the valid and the invalid set.
            guard = 0
            while self._valid(out) != valid:
                out = self._encrypt(out)
                guard += 1
                if guard > 100000:  # pragma: no cover - statistically impossible
                    raise MaskerError("SSN cycle-walk did not terminate")
        fmt = self.params["output_format"]
        if fmt == "digits":
            return out
        if fmt == "dashed":
            return "%s-%s-%s" % (out[:3], out[3:5], out[5:])
        if stripped.isdigit():
            return value.replace(stripped, out) if len(stripped) == 9 else out
        return _reinsert_digits(value, out)


class CreditCardMasker(BaseMasker):
    type_name = "credit_card"
    description = ("Card numbers (PAN): FPE on digits with valid Luhn check digit; "
                   "mode=full | last4 | first6_last4")
    default_params = {"mode": "full", "preserve_first": 0, "preserve_last": 0, "luhn": True,
                      "output_format": "preserve"}
    format_params = frozenset({"output_format"})
    families = ("string", "int", "decimal")
    injective = True
    collision_check = True  # inputs failing Luhn take a different path

    @classmethod
    def _check_params(cls, p):
        _apply_mode(p, MODES)
        _choice(p, "output_format", ("preserve", "digits", "grouped"))

    def _setup(self):
        self._cipher = FeistelCipher(self._key)

    @staticmethod
    def luhn_check_digit(body: str) -> str:
        total = 0
        for i, ch in enumerate(reversed(body)):
            d = int(ch)
            if i % 2 == 0:
                d *= 2
                if d > 9:
                    d -= 9
            total += d
        return str((10 - total % 10) % 10)

    @classmethod
    def luhn_valid(cls, number: str) -> bool:
        return len(number) > 1 and cls.luhn_check_digit(number[:-1]) == number[-1]

    def canonical(self, value):
        return re.sub(r"\D", "", value)

    def _mask(self, value):
        digits = self.canonical(value)
        if not digits:
            return value
        pf, pl = self.params["preserve_first"], self.params["preserve_last"]
        if self.params["luhn"] and pl == 0 and 12 <= len(digits) <= 19 and self.luhn_valid(digits):
            body = encrypt_text(self._cipher, digits[:-1], b"cc", pf, 0, True, False)
            out = body + self.luhn_check_digit(body)
        else:
            # Keeping the last N digits (or a non-Luhn input) means the check digit
            # cannot be recomputed; plain bijective FPE is used instead.
            out = encrypt_text(self._cipher, digits, b"cc-raw", pf, pl, True, False)
        fmt = self.params["output_format"]
        if fmt == "digits":
            return out
        if fmt == "grouped":
            return " ".join(out[i:i + 4] for i in range(0, len(out), 4))
        return _reinsert_digits(value, out)
