"""Deterministic masking algorithms.

Referential integrity rule
--------------------------
Every masker is a pure function of (secret key, *domain*, normalised value).
A *domain* is a named masking definition (e.g. ``email``, ``customer_ssn``)
that can be attached to any number of columns in any number of tables.  The
same input value in the same domain therefore always yields the same masked
value - in every table, every batch, every run and every database masked with
the same key - so joins and foreign keys keep working.

Keys are derived per domain:  domain_key = HMAC-SHA256(master_key, domain).
Changing the master key changes every masked value; keep it stable and secret.

Masker families
---------------
* bijective (collision-free) format-preserving: ``fpe``, ``account_number``,
  ``ssn``, ``phone``, ``credit_card``, ``zip`` (mode=fpe) - safe for keys
  and unique columns.
* keyed tokens: ``email``, ``hash`` - collision probability is negligible and
  checked at run time.
* dictionary substitution: ``first_name``, ``last_name``, ``full_name``,
  ``street_address``, ``city`` - realistic but NOT unique.
* generalisation / suppression: ``zip`` (mode=truncate), ``date_shift``,
  ``redact``, ``nullify``.
"""

from __future__ import annotations

import base64
import binascii
import datetime as _dt
import hashlib
import hmac
import os
import re
from typing import Any, Dict, Optional, Type

from . import data
from .fpe import FeistelCipher, encrypt_text


class MaskerError(ValueError):
    """Invalid masker configuration or a value that cannot be masked."""


# =============================================================================
# Key management
# =============================================================================
class KeyRing:
    """Holds the master secret and derives one independent key per domain."""

    def __init__(self, master_key: bytes):
        if len(master_key) < 16:
            raise MaskerError("Secret key is too short (need at least 16 bytes of entropy)")
        self._master = master_key

    @classmethod
    def from_string(cls, secret: str, min_length: int = 32) -> "KeyRing":
        secret = secret.strip()
        if len(secret) < min_length:
            raise MaskerError(
                "Secret key must be at least %d characters. Generate one with: python main.py genkey" % min_length
            )
        return cls(secret.encode("utf-8"))

    @classmethod
    def from_env(cls, env_var: str, min_length: int = 32) -> "KeyRing":
        secret = os.environ.get(env_var)
        if not secret:
            raise MaskerError(
                "Environment variable %s is not set. Generate a key with 'python main.py genkey' and set it "
                "before running (the same key must be used for every run to keep masking consistent)." % env_var
            )
        return cls.from_string(secret, min_length)

    @staticmethod
    def generate() -> str:
        return base64.urlsafe_b64encode(os.urandom(48)).decode("ascii")

    def domain_key(self, domain: str) -> bytes:
        return hmac.new(self._master, b"pythondeid-domain-v1|" + domain.encode("utf-8"), hashlib.sha256).digest()

    def fingerprint(self) -> str:
        """Non-reversible identifier of the key, safe to store in audit records."""
        return hmac.new(self._master, b"pythondeid-fingerprint", hashlib.sha256).hexdigest()[:16]


# =============================================================================
# Base classes
# =============================================================================
class BaseMasker:
    type_name = ""
    description = ""
    default_params: Dict[str, Any] = {}
    #: column type families this masker may be applied to
    families = ("string",)
    #: True if two different inputs can never produce the same output
    injective = False
    #: True if the engine should actively check for output collisions
    collision_check = False

    def __init__(self, domain: str, key: bytes, params: Optional[Dict[str, Any]] = None):
        self.domain = domain
        self._key = key
        self.params = self.validate_params(params or {})
        self._setup()

    # -- configuration --------------------------------------------------------
    @classmethod
    def validate_params(cls, params: Dict[str, Any]) -> Dict[str, Any]:
        unknown = set(params) - set(cls.default_params)
        if unknown:
            raise MaskerError(
                "Unknown parameter(s) %s for mask type '%s'. Allowed: %s"
                % (sorted(unknown), cls.type_name, sorted(cls.default_params) or "none")
            )
        merged = dict(cls.default_params)
        merged.update(params)
        cls._check_params(merged)
        return merged

    @classmethod
    def _check_params(cls, p: Dict[str, Any]) -> None:
        pass

    def _setup(self) -> None:
        pass

    # -- helpers --------------------------------------------------------------
    def _digest(self, *parts: str) -> bytes:
        return hmac.new(self._key, "\x1f".join(parts).encode("utf-8"), hashlib.sha256).digest()

    def _int(self, *parts: str) -> int:
        return int.from_bytes(self._digest(*parts), "big")

    def _pick(self, choices, *parts: str) -> str:
        return choices[self._int(*parts) % len(choices)]

    # -- API ------------------------------------------------------------------
    def canonical(self, value: str) -> str:
        """The normalised form the mask is derived from (used for collision checks)."""
        return value

    def mask(self, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        if value.strip() == "":
            return value
        return self._mask(value)

    def _mask(self, value: str) -> Optional[str]:
        raise NotImplementedError


def _non_negative_int(p: Dict[str, Any], *names: str) -> None:
    for n in names:
        if not isinstance(p[n], int) or isinstance(p[n], bool) or p[n] < 0:
            raise MaskerError("Parameter '%s' must be a non-negative integer" % n)


def _match_case(template: str, value: str) -> str:
    if template.isupper():
        return value.upper()
    if template.islower():
        return value.lower()
    return value


def _reinsert_digits(template: str, digits: str) -> str:
    it = iter(digits)
    return "".join(next(it) if ch.isdigit() else ch for ch in template)


# =============================================================================
# Format-preserving / bijective maskers
# =============================================================================
class FpeMasker(BaseMasker):
    type_name = "fpe"
    description = "Format-preserving encryption of letters/digits (bijective, keeps separators and length)"
    default_params = {"preserve_first": 0, "preserve_last": 0, "digits": True, "letters": True}
    families = ("string", "int", "decimal")
    injective = True

    @classmethod
    def _check_params(cls, p):
        _non_negative_int(p, "preserve_first", "preserve_last")
        if not (p["digits"] or p["letters"]):
            raise MaskerError("At least one of 'digits' or 'letters' must be true")

    def _setup(self):
        self._cipher = FeistelCipher(self._key)

    def _mask(self, value):
        return encrypt_text(
            self._cipher, value, self.type_name.encode(),
            self.params["preserve_first"], self.params["preserve_last"],
            self.params["digits"], self.params["letters"],
        )


class AccountNumberMasker(FpeMasker):
    type_name = "account_number"
    description = "Account/IBAN/member numbers: FPE keeping length, format and optional leading/trailing chars"


class PhoneMasker(FpeMasker):
    type_name = "phone"
    description = "Phone numbers: FPE on digits only, punctuation/format preserved"
    default_params = {"preserve_first": 0, "preserve_last": 0, "digits": True, "letters": False}


class SsnMasker(BaseMasker):
    type_name = "ssn"
    description = "US SSN: bijective FPE on the 9 digits; realistic=true keeps output inside valid SSA ranges"
    default_params = {"output_format": "preserve", "realistic": True, "zero_pad": True}
    families = ("string", "int", "decimal")
    injective = True

    @classmethod
    def _check_params(cls, p):
        if p["output_format"] not in ("preserve", "dashed", "digits"):
            raise MaskerError("ssn.output_format must be one of preserve, dashed, digits")

    def _setup(self):
        self._cipher = FeistelCipher(self._key)

    @staticmethod
    def _valid(d: str) -> bool:
        area, group, serial = d[:3], d[3:5], d[5:]
        return area not in ("000", "666") and area[0] != "9" and group != "00" and serial != "0000"

    def canonical(self, value):
        digits = re.sub(r"\D", "", value)
        if self.params["zero_pad"] and value.strip().isdigit() and len(digits) < 9:
            digits = digits.zfill(9)
        return digits if len(digits) == 9 else value

    def _mask(self, value):
        stripped = value.strip()
        digits = self.canonical(value)
        if len(digits) != 9 or not digits.isdigit():
            # Not an SSN shape - still mask it reversibly-safe instead of leaking it.
            return encrypt_text(self._cipher, value, b"ssn-nonstandard")
        valid = self._valid(digits)
        out = self._cipher.encrypt_digits(digits, b"ssn")
        if self.params["realistic"]:
            # Cycle-walking keeps the map a bijection within valid and invalid sets.
            guard = 0
            while self._valid(out) != valid:
                out = self._cipher.encrypt_digits(out, b"ssn")
                guard += 1
                if guard > 10000:  # pragma: no cover - statistically impossible
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
    description = "Card numbers (PAN): FPE on digits, optional BIN/last-4 preservation, valid Luhn check digit"
    default_params = {"preserve_first": 0, "preserve_last": 0, "luhn": True}
    families = ("string", "int", "decimal")
    injective = True
    collision_check = True  # inputs failing Luhn take a different path

    @classmethod
    def _check_params(cls, p):
        _non_negative_int(p, "preserve_first", "preserve_last")

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

    def _mask(self, value):
        digits = re.sub(r"\D", "", value)
        pf, pl = self.params["preserve_first"], self.params["preserve_last"]
        if self.params["luhn"] and pl == 0 and 12 <= len(digits) <= 19 and self.luhn_valid(digits):
            body = encrypt_text(self._cipher, digits[:-1], b"cc", pf, 0, True, False)
            out = body + self.luhn_check_digit(body)
        else:
            # Keeping the last N digits (or a non-Luhn input) means the check digit
            # cannot be recomputed; plain bijective FPE is used instead.
            out = encrypt_text(self._cipher, digits, b"cc-raw", pf, pl, True, False)
        return _reinsert_digits(value, out)


# =============================================================================
# Keyed tokens
# =============================================================================
class EmailMasker(BaseMasker):
    type_name = "email"
    description = "Email: deterministic token local-part @ safe domain (case-insensitive, unique)"
    default_params = {"domain": "example.com", "preserve_domain": False, "prefix": "user", "token_length": 12}
    collision_check = True
    injective = True

    @classmethod
    def _check_params(cls, p):
        if not isinstance(p["token_length"], int) or not 6 <= p["token_length"] <= 52:
            raise MaskerError("email.token_length must be an integer between 6 and 52")
        if not p["preserve_domain"] and not re.match(r"^[A-Za-z0-9.-]+$", str(p["domain"])):
            raise MaskerError("email.domain must be a plain domain name, e.g. example.com")

    def canonical(self, value):
        return value.strip().lower()

    def _mask(self, value):
        norm = self.canonical(value)
        local, _, domain = norm.rpartition("@")
        if not local:
            local, domain = norm, ""
        token = base64.b32encode(self._digest("email", norm)).decode("ascii").lower().rstrip("=")
        token = token[: self.params["token_length"]]
        out_domain = domain if (self.params["preserve_domain"] and domain) else self.params["domain"]
        return "%s%s@%s" % (self.params["prefix"], token, out_domain)


class HashMasker(BaseMasker):
    type_name = "hash"
    description = "Keyed HMAC-SHA256 hex token (irreversible, deterministic)"
    default_params = {"length": 32, "prefix": "", "uppercase": False, "case_sensitive": True}
    collision_check = True
    injective = True

    @classmethod
    def _check_params(cls, p):
        if not isinstance(p["length"], int) or not 8 <= p["length"] <= 64:
            raise MaskerError("hash.length must be an integer between 8 and 64")

    def canonical(self, value):
        return value if self.params["case_sensitive"] else value.strip().lower()

    def _mask(self, value):
        token = binascii.hexlify(self._digest("hash", self.canonical(value))).decode()[: self.params["length"]]
        return self.params["prefix"] + (token.upper() if self.params["uppercase"] else token)


# =============================================================================
# Dictionary substitution (realistic, NOT unique)
# =============================================================================
class FirstNameMasker(BaseMasker):
    type_name = "first_name"
    description = "Replace with a deterministic first name from a built-in list"

    def canonical(self, value):
        return value.strip().lower()

    def _mask(self, value):
        return _match_case(value.strip(), self._pick(data.FIRST_NAMES, "first", self.canonical(value)))


class LastNameMasker(FirstNameMasker):
    type_name = "last_name"
    description = "Replace with a deterministic last name from a built-in list"

    def _mask(self, value):
        return _match_case(value.strip(), self._pick(data.LAST_NAMES, "last", self.canonical(value)))


class FullNameMasker(FirstNameMasker):
    type_name = "full_name"
    description = "Replace 'First [Middle] Last' / 'Last, First' token by token (consistent with name parts)"

    def _mask(self, value):
        text = value.strip()
        if "," in text:
            last, _, first = text.partition(",")
            return "%s, %s" % (self._last(last.strip()), " ".join(self._first(t) for t in first.split()))
        tokens = text.split()
        if len(tokens) == 1:
            return self._last(tokens[0])
        middle = [_match_case(t, t[0].upper() + ".") if len(t.rstrip(".")) <= 1 else self._first(t) for t in tokens[1:-1]]
        return " ".join([self._first(tokens[0])] + middle + [self._last(tokens[-1])])

    def _first(self, token):
        return _match_case(token, self._pick(data.FIRST_NAMES, "first", token.lower()))

    def _last(self, token):
        return _match_case(token, self._pick(data.LAST_NAMES, "last", token.lower()))


class StreetAddressMasker(FirstNameMasker):
    type_name = "street_address"
    description = "Replace with a deterministic synthetic street address"

    def _mask(self, value):
        norm = self.canonical(value)
        number = 100 + self._int("addr-n", norm) % 9900
        street = self._pick(data.STREET_NAMES, "addr-s", norm)
        suffix = self._pick(data.STREET_SUFFIXES, "addr-x", norm)
        return _match_case(value.strip(), "%d %s %s" % (number, street, suffix))


class CityMasker(FirstNameMasker):
    type_name = "city"
    description = "Replace with a deterministic city name from a built-in list"

    def _mask(self, value):
        return _match_case(value.strip(), self._pick(data.CITIES, "city", self.canonical(value)))


# =============================================================================
# Generalisation / suppression
# =============================================================================
class ZipMasker(BaseMasker):
    type_name = "zip"
    description = "ZIP/postal: mode=truncate keeps first N digits (HIPAA style), mode=fpe is bijective"
    default_params = {"mode": "truncate", "keep_digits": 3, "fill": "0"}
    families = ("string", "int")

    @classmethod
    def _check_params(cls, p):
        if p["mode"] not in ("truncate", "fpe"):
            raise MaskerError("zip.mode must be 'truncate' or 'fpe'")
        _non_negative_int(p, "keep_digits")
        if not (isinstance(p["fill"], str) and len(p["fill"]) == 1 and p["fill"].isdigit()):
            raise MaskerError("zip.fill must be a single digit")

    def _setup(self):
        self._cipher = FeistelCipher(self._key)
        if self.params["mode"] == "fpe":
            self.injective = True

    def _mask(self, value):
        if self.params["mode"] == "fpe":
            return encrypt_text(self._cipher, value, b"zip", digits=True, letters=False)
        seen = 0
        out = []
        for ch in value:
            if ch.isdigit():
                out.append(ch if seen < self.params["keep_digits"] else self.params["fill"])
                seen += 1
            else:
                out.append(ch)
        return "".join(out)


_DATE_ISO = re.compile(r"^(\s*)(\d{4})-(\d{2})-(\d{2})(.*)$", re.S)
_DATE_US = re.compile(r"^(\s*)(\d{1,2})/(\d{1,2})/(\d{4})(.*)$", re.S)
_DATE_COMPACT = re.compile(r"^(\s*)(\d{4})(\d{2})(\d{2})(\s*)$")


class DateShiftMasker(BaseMasker):
    type_name = "date_shift"
    description = "Shift dates by a deterministic +/- N day offset derived from the value, or generalise"
    default_params = {"max_days": 365, "generalize": "none"}
    families = ("string", "date")

    @classmethod
    def _check_params(cls, p):
        if not isinstance(p["max_days"], int) or p["max_days"] < 1:
            raise MaskerError("date_shift.max_days must be a positive integer")
        if p["generalize"] not in ("none", "year", "month"):
            raise MaskerError("date_shift.generalize must be none, year or month")

    def _parse(self, value):
        m = _DATE_ISO.match(value)
        if m:
            lead, y, mo, d, rest = m.groups()
            return lead, _dt.date(int(y), int(mo), int(d)), rest, "iso"
        m = _DATE_US.match(value)
        if m:
            lead, mo, d, y, rest = m.groups()
            return lead, _dt.date(int(y), int(mo), int(d)), rest, "us"
        m = _DATE_COMPACT.match(value)
        if m:
            lead, y, mo, d, rest = m.groups()
            return lead, _dt.date(int(y), int(mo), int(d)), rest, "compact"
        raise MaskerError("Unrecognised date format: expected YYYY-MM-DD, MM/DD/YYYY or YYYYMMDD")

    def canonical(self, value):
        try:
            return self._parse(value)[1].isoformat()
        except (MaskerError, ValueError):
            return value

    def _mask(self, value):
        try:
            lead, date, rest, style = self._parse(value)
        except ValueError as exc:
            raise MaskerError("Invalid date '%s': %s" % (value, exc))
        gen = self.params["generalize"]
        if gen == "year":
            new = _dt.date(date.year, 1, 1)
        elif gen == "month":
            new = _dt.date(date.year, date.month, 1)
        else:
            span = self.params["max_days"]
            o = self._int("date", date.isoformat()) % (2 * span)
            offset = o - span if o < span else o - span + 1  # never zero
            try:
                new = date + _dt.timedelta(days=offset)
            except OverflowError:
                new = date - _dt.timedelta(days=offset)
        if gen != "none":
            rest = re.sub(r"\d", "0", rest) if rest.strip() else rest
        if style == "iso":
            body = new.isoformat()
        elif style == "us":
            body = "%02d/%02d/%04d" % (new.month, new.day, new.year)
        else:
            body = new.strftime("%Y%m%d")
        return lead + body + rest


class RedactMasker(BaseMasker):
    type_name = "redact"
    description = "Replace with a constant (or same-length mask characters)"
    default_params = {"value": "REDACTED", "preserve_length": False, "char": "X"}

    def _mask(self, value):
        if self.params["preserve_length"]:
            return "".join(ch if ch.isspace() else self.params["char"] for ch in value)
        return str(self.params["value"])


class NullifyMasker(BaseMasker):
    type_name = "nullify"
    description = "Set the column to NULL"
    families = ("string", "int", "decimal", "date", "other")

    def mask(self, value):
        return None


# =============================================================================
# Registry
# =============================================================================
MASKERS: Dict[str, Type[BaseMasker]] = {
    cls.type_name: cls
    for cls in (
        EmailMasker, SsnMasker, AccountNumberMasker, CreditCardMasker, PhoneMasker, FpeMasker, HashMasker,
        FirstNameMasker, LastNameMasker, FullNameMasker, StreetAddressMasker, CityMasker, ZipMasker,
        DateShiftMasker, RedactMasker, NullifyMasker,
    )
}


def get_masker_class(type_name: str) -> Type[BaseMasker]:
    try:
        return MASKERS[type_name]
    except KeyError:
        raise MaskerError("Unknown mask type '%s'. Available: %s" % (type_name, ", ".join(sorted(MASKERS))))


def create_masker(type_name: str, domain: str, keyring: KeyRing, params: Optional[Dict[str, Any]] = None) -> BaseMasker:
    return get_masker_class(type_name)(domain, keyring.domain_key(domain), params)


def is_injective(type_name: str, params: Optional[Dict[str, Any]] = None) -> bool:
    cls = get_masker_class(type_name)
    if cls is ZipMasker:
        return (params or {}).get("mode", "truncate") == "fpe"
    return cls.injective


__all__ = [
    "KeyRing", "MaskerError", "BaseMasker", "MASKERS", "get_masker_class", "create_masker", "is_injective",
]
