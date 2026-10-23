"""Deterministic masking algorithms.

Consistency guarantee (tables, databases, servers)
--------------------------------------------------
Every masker is a pure function of

    (master secret, ALGORITHM_VERSION, domain name, domain params, canonical input)

and nothing else - no randomness, no run id, no server name, no row order.
Two servers that use the same secret key and the same rules file therefore
produce byte-identical masked values for the same input, in every table,
database, batch and run.  ``security.expected_key_fingerprint`` and
``python main.py test-vectors`` let you prove that every environment is
configured identically.

*Canonical input* removes representation differences before masking:
``John.Doe@Mail.COM`` = ``john.doe@mail.com``, ``123-45-6789`` = ``123456789``,
and with ``normalize: digits`` an account number stored as ``'0000012345'``
(varchar) and ``12345`` (bigint) masks to the same number.

Keys are derived per domain:  domain_key = HMAC-SHA256(master, "v1|" + domain).

Masker families
---------------
* bijective (collision-free) format-preserving: ``fpe``, ``account_number``,
  ``ssn``, ``phone``, ``credit_card``, ``zip`` (mode=fpe) - safe for keys.
* keyed tokens: ``email``, ``hash`` - collision-checked at run time.
* dictionary substitution: ``first_name``, ``last_name``, ``full_name``,
  ``account_name`` (people and businesses), ``street_address``, ``city`` - realistic, NOT unique.
* generalisation / suppression: ``zip`` (truncate), ``date_shift`` (per value
  or per person), ``redact``, ``nullify``.
* ``free_text``: scrub PII patterns inside notes/comments (optionally masking
  each hit with another domain, so a SSN in a note matches the SSN column).
"""

from __future__ import annotations

import base64
import binascii
import datetime as _dt
import hashlib
import hmac
import os
import re
from typing import Any, Dict, FrozenSet, List, Optional, Tuple, Type

from . import data
from .fpe import FeistelCipher, encrypt_text

#: Bump only if an algorithm changes output. Rules may pin it (algorithm_version: 1).
ALGORITHM_VERSION = 1


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
                "before running (the same key must be used on every server to keep masking consistent)." % env_var
            )
        return cls.from_string(secret, min_length)

    @staticmethod
    def generate() -> str:
        return base64.urlsafe_b64encode(os.urandom(48)).decode("ascii")

    def domain_key(self, domain: str) -> bytes:
        return hmac.new(self._master, b"pythondeid-domain-v1|" + domain.encode("utf-8"), hashlib.sha256).digest()

    def fingerprint(self) -> str:
        """Non-reversible identifier of the key, safe to store in audit records and config."""
        return hmac.new(self._master, b"pythondeid-fingerprint", hashlib.sha256).hexdigest()[:16]


# =============================================================================
# Base classes
# =============================================================================
class BaseMasker:
    type_name = ""
    description = ""
    default_params: Dict[str, Any] = {}
    #: params that only change how the result is rendered; columns may override them
    format_params: FrozenSet[str] = frozenset()
    #: column type families this masker may be applied to
    families: Tuple[str, ...] = ("string",)
    #: True if two different inputs can never produce the same output
    injective = False
    #: True if the engine should actively check for output collisions
    collision_check = False
    #: True if the masker uses a second "entity" value (e.g. person id for date shifting)
    uses_entity = False

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

    @classmethod
    def entity_required(cls, params: Dict[str, Any]) -> bool:
        return False

    @classmethod
    def referenced_domains(cls, params: Dict[str, Any]) -> List[str]:
        return []

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

    def mask(self, value: Optional[str], entity: Optional[str] = None) -> Optional[str]:
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


def _choice(p: Dict[str, Any], name: str, allowed) -> None:
    if p[name] not in allowed:
        raise MaskerError("Parameter '%s' must be one of %s (got %r)" % (name, ", ".join(map(str, allowed)), p[name]))


def _match_case(template: str, value: str) -> str:
    if template.isupper():
        return value.upper()
    if template.islower():
        return value.lower()
    return value


def _reinsert_digits(template: str, digits: str) -> str:
    it = iter(digits)
    return "".join(next(it) if ch.isdigit() else ch for ch in template)


# Partial de-identification options shared by ssn / account_number / credit_card.
#   full          - every digit/letter is de-identified (default, recommended)
#   last4         - keep the last 4 digits, de-identify the rest
#   first6_last4  - (cards) keep BIN + last 4, PCI-DSS display style
MODES = ("full", "last4", "first6_last4")


def _apply_mode(p: Dict[str, Any], allowed=("full", "last4")) -> None:
    _choice(p, "mode", allowed)
    _non_negative_int(p, *(n for n in ("preserve_first", "preserve_last") if n in p))
    if p["mode"] == "full":
        return
    want_first, want_last = (6, 4) if p["mode"] == "first6_last4" else (0, 4)
    for name, want in (("preserve_first", want_first), ("preserve_last", want_last)):
        if name not in p:
            continue
        if p[name] not in (0, want):
            raise MaskerError("mode=%s conflicts with %s=%s; set only one of them" % (p["mode"], name, p[name]))
        p[name] = want


# =============================================================================
# Format-preserving / bijective maskers
# =============================================================================
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


class PhoneMasker(FpeMasker):
    type_name = "phone"
    description = "Phone numbers: FPE on digits only, punctuation/format preserved"
    default_params = dict(FpeMasker.default_params, letters=False)


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


# =============================================================================
# Keyed tokens
# =============================================================================
class EmailMasker(BaseMasker):
    type_name = "email"
    description = "Email: deterministic token local-part @ safe domain (case-insensitive, unique)"
    default_params = {"domain": "example.com", "preserve_domain": False, "prefix": "user", "token_length": 16}
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


# Name columns choose their algorithm with one setting; each method delegates to an existing masker.
#   realistic - fake names (this class / account_name logic)
#   hash      - HashMasker token, case-insensitive (unique; usable on key/unique columns)
#   redact    - RedactMasker constant
NAME_METHODS = ("realistic", "hash", "redact")
NAME_METHOD_PARAMS = {"method": "realistic", "hash_length": 16, "hash_prefix": "", "redact_value": "REDACTED"}


class FullNameMasker(FirstNameMasker):
    type_name = "full_name"
    description = ("Person names: method=realistic (fake 'First M. Last', default) | hash (unique token) | "
                   "redact (constant)")
    default_params = dict(NAME_METHOD_PARAMS)

    @classmethod
    def _check_params(cls, p):
        _choice(p, "method", NAME_METHODS)
        if not isinstance(p["hash_length"], int) or not 8 <= p["hash_length"] <= 64:
            raise MaskerError("hash_length must be an integer between 8 and 64")

    def _setup(self):
        method = self.params["method"]
        self._delegate: Optional[BaseMasker] = None
        if method == "hash":
            self._delegate = HashMasker(self.domain, self._key, {
                "length": self.params["hash_length"], "prefix": self.params["hash_prefix"], "case_sensitive": False})
            self.injective = True
            self.collision_check = True
        elif method == "redact":
            self._delegate = RedactMasker(self.domain, self._key, {"value": self.params["redact_value"]})

    def mask(self, value, entity=None):
        if self._delegate is not None:
            return self._delegate.mask(value)
        return super().mask(value, entity)

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


_TOKEN_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9.'/]*|[^A-Za-z0-9\s]+|\s+")


class AccountNameMasker(FullNameMasker):
    """Account / customer / party names that may be a person OR a business.

    * person ("LAURA H TALKO", "SMITH, JOHN")  -> fake person name, like full_name
    * business ("ACME DEVELOPMENT INC")         -> "SUMMIT DEVELOPMENT INC": identifying words replaced
      by company-style words; legal suffixes and generic industry words kept (keep_industry_words)
    * person-held entity ("JOHN SMITH REVOCABLE TRUST") -> "STEPHEN STEWART REVOCABLE TRUST"
    Punctuation, spacing and upper/lower case are kept.  Each word maps deterministically, so the same
    business name masks identically in every table and server.  Not unique (do not use on keys).
    """

    type_name = "account_name"
    description = ("Account/customer names (people or businesses): method=realistic -> fake person names / fake "
                   "company names keeping INC/LLC/LTD and industry words; method=hash | redact")
    default_params = dict(NAME_METHOD_PARAMS, keep_industry_words=True, extra_business_words=[], keep_numbers=False)

    @classmethod
    def _check_params(cls, p):
        super()._check_params(p)
        if not isinstance(p["extra_business_words"], list):
            raise MaskerError("account_name.extra_business_words must be a list of words, e.g. [BANCSHARES, LABS]")

    def _setup(self):
        super()._setup()
        self._generic = (data.BUSINESS_SUFFIXES | data.INDUSTRY_WORDS
                         | {str(w).upper().rstrip(".") for w in self.params["extra_business_words"]})
        self._first_set = {n.upper() for n in data.FIRST_NAMES}

    @staticmethod
    def _norm(token):
        return token.upper().rstrip(".,")

    def classify(self, value: str) -> str:
        words = [self._norm(t) for t in _TOKEN_RE.findall(value) if t.strip() and t[0].isalnum()]
        if any(w in data.PERSONAL_ENTITY_WORDS for w in words):
            return "person_entity"
        if any(w in self._generic for w in words) or "&" in value or any(ch.isdigit() for ch in value):
            return "business"
        return "person"

    def _business_word(self, token):
        return _match_case(token, self._pick(data.COMPANY_WORDS, "biz", token.lower()))

    def _person_word(self, token):
        if self._norm(token) in self._first_set:
            return self._first(token)
        return self._last(token)

    def _mask(self, value):
        kind = self.classify(value)
        if kind == "person":
            return super()._mask(value)
        out = []
        for tok in _TOKEN_RE.findall(value):
            w = self._norm(tok)
            if not tok.strip() or not tok[0].isalnum() or w in data.CONNECTOR_WORDS:
                out.append(tok)
            elif w in data.PERSONAL_ENTITY_WORDS or (self.params["keep_industry_words"] and w in self._generic):
                out.append(tok)
            elif tok.isdigit():
                if self.params["keep_numbers"]:
                    out.append(tok)
                else:
                    n = self._int("biz-num", tok)
                    digits = str(n % (10 ** len(tok))).zfill(len(tok))
                    out.append(digits if len(tok) == 1 or digits[0] != "0" else "1" + digits[1:])
            elif len(w) == 1:
                out.append(_match_case(tok, "ABCDEFGHJKLMNPRSTW"[self._int("biz-init", w) % 18]))
            else:
                trail = tok[len(tok.rstrip(".,")):]
                core = tok[: len(tok) - len(trail)]
                repl = self._person_word(core) if kind == "person_entity" else self._business_word(core)
                out.append(repl + trail)
        return "".join(out)


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
        _choice(p, "mode", ("truncate", "fpe"))
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


def normalize_entity(value: str, how: str) -> str:
    if how == "digits":
        d = re.sub(r"\D", "", value)
        return (d.lstrip("0") or "0") if d else value.strip().lower()
    if how == "trim_lower":
        return value.strip().lower()
    return value


class DateShiftMasker(BaseMasker):
    type_name = "date_shift"
    description = ("Shift dates by a deterministic +/- N day offset. shift_by=entity uses ONE offset per person "
                   "(column's entity_column), preserving intervals between that person's dates")
    default_params = {"max_days": 365, "generalize": "none", "shift_by": "value", "entity_normalize": "trim_lower"}
    families = ("string", "date")
    uses_entity = True

    @classmethod
    def _check_params(cls, p):
        if not isinstance(p["max_days"], int) or isinstance(p["max_days"], bool) or p["max_days"] < 1:
            raise MaskerError("date_shift.max_days must be a positive integer")
        _choice(p, "generalize", ("none", "year", "month"))
        _choice(p, "shift_by", ("value", "entity"))
        _choice(p, "entity_normalize", ("none", "trim_lower", "digits"))

    @classmethod
    def entity_required(cls, params):
        return params.get("shift_by") == "entity"

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

    def offset_days(self, seed: str) -> int:
        span = self.params["max_days"]
        o = self._int("date", seed) % (2 * span)
        return o - span if o < span else o - span + 1  # never zero

    def mask(self, value, entity=None):
        if value is None:
            return None
        if value.strip() == "":
            return value
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
            if self.params["shift_by"] == "entity" and entity is not None and entity.strip() != "":
                seed = "entity\x1f" + normalize_entity(entity, self.params["entity_normalize"])
            else:
                seed = date.isoformat()  # no person id on this row: fall back to per-value shift
            offset = self.offset_days(seed)
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

    def mask(self, value, entity=None):
        return None


# =============================================================================
# Free text (notes, comments, descriptions)
# =============================================================================
BUILTIN_DETECTORS: Dict[str, str] = {
    # order = priority when patterns overlap
    "email": r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
    "credit_card": r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)",
    "ssn": r"(?<!\d)\d{3}[- ]\d{2}[- ]\d{4}(?!\d)",
    "phone": r"(?<![\w])(?:\+?\d{1,3}[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}(?!\d)",
    "ip_address": r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])",
    "date": r"(?<!\d)(?:\d{4}-\d{2}-\d{2}|\d{1,2}/\d{1,2}/\d{4})(?!\d)",
}
DEFAULT_DETECTORS = {
    "email": {"action": "tag", "tag": "[EMAIL]"},
    "credit_card": {"action": "tag", "tag": "[CARD]"},
    "ssn": {"action": "tag", "tag": "[SSN]"},
    "phone": {"action": "tag", "tag": "[PHONE]"},
}


class FreeTextMasker(BaseMasker):
    """Options (all via config):

    mode: scrub (default) | redact | nullify | hash
    detectors:            which built-in PII patterns to find and what to do with each hit
        email:  {action: mask, domain: email}   # same token as the Email columns
        ssn:    {action: tag, tag: "[SSN]"}     # replace with a fixed tag
        phone:  {action: remove}                # delete the hit
    custom_patterns:      [{name: member_id, regex: "MBR\\d{8}", action: mask, domain: account_number}]
    on_overflow:          truncate (default) | error  - if the scrubbed text exceeds the column length
    """

    type_name = "free_text"
    description = ("Notes/comments: mode=scrub finds email/SSN/card/phone/IP/date/custom regex hits and tags, "
                   "removes or masks them with another domain; or mode=redact|nullify|hash")
    default_params = {
        "mode": "scrub", "replacement": "[REDACTED]", "detectors": DEFAULT_DETECTORS,
        "custom_patterns": [], "on_overflow": "truncate",
    }

    @classmethod
    def _check_params(cls, p):
        _choice(p, "mode", ("scrub", "redact", "nullify", "hash"))
        _choice(p, "on_overflow", ("truncate", "error"))
        if not isinstance(p["detectors"], dict):
            raise MaskerError("free_text.detectors must be a mapping of detector -> {action: ...}")
        for name, spec in p["detectors"].items():
            if name not in BUILTIN_DETECTORS:
                raise MaskerError("Unknown free_text detector '%s'. Built-in: %s" % (name, ", ".join(BUILTIN_DETECTORS)))
            cls._check_action(name, spec)
        if not isinstance(p["custom_patterns"], list):
            raise MaskerError("free_text.custom_patterns must be a list")
        for cp in p["custom_patterns"]:
            if not isinstance(cp, dict) or not cp.get("name") or not cp.get("regex"):
                raise MaskerError("each custom_pattern needs 'name' and 'regex'")
            try:
                re.compile(cp["regex"])
            except re.error as exc:
                raise MaskerError("custom_pattern '%s' has an invalid regex: %s" % (cp["name"], exc))
            cls._check_action(cp["name"], cp)

    @staticmethod
    def _check_action(name, spec):
        if not isinstance(spec, dict):
            raise MaskerError("detector '%s' must be a mapping like {action: tag}" % name)
        action = spec.get("action", "tag")
        if action not in ("tag", "remove", "mask"):
            raise MaskerError("detector '%s': action must be tag, remove or mask" % name)
        if action == "mask" and not spec.get("domain"):
            raise MaskerError("detector '%s': action=mask needs a 'domain' to mask hits with" % name)

    @classmethod
    def referenced_domains(cls, params):
        specs = list((params.get("detectors") or {}).values()) + list(params.get("custom_patterns") or [])
        return [s["domain"] for s in specs if isinstance(s, dict) and s.get("action") == "mask"]

    def _setup(self):
        self.resolver: Dict[str, BaseMasker] = {}
        self._rules: List[Tuple[str, Dict[str, Any]]] = []
        parts = []
        for i, (name, spec) in enumerate(self.params["detectors"].items()):
            parts.append("(?P<b%d>%s)" % (i, BUILTIN_DETECTORS[name]))
            self._rules.append((name, spec))
        offset = len(self._rules)
        for j, cp in enumerate(self.params["custom_patterns"]):
            parts.append("(?P<b%d>%s)" % (offset + j, cp["regex"]))
            self._rules.append((cp["name"], cp))
        self._regex = re.compile("|".join(parts)) if parts else None

    def set_resolver(self, maskers: Dict[str, BaseMasker]) -> None:
        missing = [d for d in self.referenced_domains(self.params) if d not in maskers]
        if missing:
            raise MaskerError("free_text domain '%s' references undefined domain(s): %s" % (self.domain, missing))
        self.resolver = maskers

    def _replace(self, m):
        idx = int(m.lastgroup[1:])
        name, spec = self._rules[idx]
        hit = m.group(0)
        if name == "credit_card" and not CreditCardMasker.luhn_valid(re.sub(r"\D", "", hit)):
            return hit  # long digit runs that are not card numbers
        action = spec.get("action", "tag")
        if action == "remove":
            return ""
        if action == "mask":
            masker = self.resolver.get(spec["domain"])
            if masker is None:
                raise MaskerError("free_text: domain '%s' is not available" % spec["domain"])
            masked = masker.mask(hit)
            return "" if masked is None else masked
        return str(spec.get("tag") or "[%s]" % name.upper())

    def mask(self, value, entity=None):
        if value is None:
            return None
        mode = self.params["mode"]
        if mode == "nullify":
            return None
        if value.strip() == "":
            return value
        if mode == "redact":
            return str(self.params["replacement"])
        if mode == "hash":
            return binascii.hexlify(self._digest("text", value)).decode()[:32]
        return self._regex.sub(self._replace, value) if self._regex else value


# =============================================================================
# Registry
# =============================================================================
MASKERS: Dict[str, Type[BaseMasker]] = {
    cls.type_name: cls
    for cls in (
        EmailMasker, SsnMasker, AccountNumberMasker, CreditCardMasker, PhoneMasker, FpeMasker, HashMasker,
        FirstNameMasker, LastNameMasker, FullNameMasker, StreetAddressMasker, CityMasker, ZipMasker,
        DateShiftMasker, RedactMasker, NullifyMasker, FreeTextMasker, AccountNameMasker,
    )
}


def get_masker_class(type_name: str) -> Type[BaseMasker]:
    try:
        return MASKERS[type_name]
    except KeyError:
        raise MaskerError("Unknown mask type '%s'. Available: %s" % (type_name, ", ".join(sorted(MASKERS))))


def create_masker(type_name: str, domain: str, keyring: KeyRing, params: Optional[Dict[str, Any]] = None) -> BaseMasker:
    return get_masker_class(type_name)(domain, keyring.domain_key(domain), params)


def build_maskers(domains, keyring: KeyRing) -> Dict[str, BaseMasker]:
    """One masker per domain (DomainRule-like objects with name/type/params), with free-text links resolved."""
    maskers = {d.name: create_masker(d.type, d.name, keyring, d.params) for d in domains}
    for m in maskers.values():
        if isinstance(m, FreeTextMasker):
            m.set_resolver(maskers)
    return maskers


def column_masker(base: BaseMasker, keyring: KeyRing, overrides: Dict[str, Any]) -> BaseMasker:
    """A masker for one column with format-only overrides; identical identity (same domain key)."""
    if not overrides:
        return base
    bad = set(overrides) - set(base.format_params)
    if bad:
        raise MaskerError("Column overrides %s are not allowed for '%s' (allowed: %s)"
                          % (sorted(bad), base.type_name, sorted(base.format_params) or "none"))
    m = type(base)(base.domain, keyring.domain_key(base.domain), dict(base.params, **overrides))
    if isinstance(base, FreeTextMasker):
        m.set_resolver(base.resolver)
    return m


def is_injective(type_name: str, params: Optional[Dict[str, Any]] = None) -> bool:
    cls = get_masker_class(type_name)
    if cls is ZipMasker:
        return (params or {}).get("mode", "truncate") == "fpe"
    if issubclass(cls, FullNameMasker):
        return (params or {}).get("method", "realistic") == "hash"
    return cls.injective


__all__ = [
    "ALGORITHM_VERSION", "KeyRing", "MaskerError", "BaseMasker", "MASKERS", "MODES", "get_masker_class",
    "create_masker", "build_maskers", "column_masker", "is_injective", "normalize_entity",
]
