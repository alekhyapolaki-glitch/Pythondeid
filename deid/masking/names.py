"""Name and location maskers (people, accounts/businesses, street addresses, cities) with the
method choice realistic | hash | redact."""

from __future__ import annotations

import re
from typing import Optional

from . import data
from .base import BaseMasker, MaskerError, _choice, _match_case
from .generalize import RedactMasker
from .tokens import HashMasker


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


class MethodChoiceMasker(FirstNameMasker):
    """Base for maskers whose algorithm is chosen by 'method': realistic | hash | redact."""

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


class FullNameMasker(MethodChoiceMasker):
    type_name = "full_name"
    description = ("Person names: method=realistic (fake 'First M. Last', default) | hash (unique token) | "
                   "redact (constant)")

    def _mask(self, value):
        text = value.strip()
        if "," in text:
            last, _, first = text.partition(",")
            return "%s, %s" % (self._last(last.strip()), " ".join(self._first(t) for t in first.split()))
        tokens = text.split()
        if len(tokens) == 1:
            return self._last(tokens[0])
        middle = [_match_case(t, t[0].upper() + ".") if len(t.rstrip(".")) <= 1 else self._first(t) for t in tokens[1:-1]]
        return " ".join([self._first(tokens[0]), *middle, self._last(tokens[-1])])

    def _first(self, token):
        return _match_case(token, self._pick(data.FIRST_NAMES, "first", token.lower()))

    def _last(self, token):
        return _match_case(token, self._pick(data.LAST_NAMES, "last", token.lower()))


class StreetAddressMasker(MethodChoiceMasker):
    type_name = "street_address"
    description = "Street addresses: method=realistic (fake '4821 Maple Ave', default) | hash | redact"

    def _mask(self, value):
        norm = self.canonical(value)
        number = 100 + self._int("addr-n", norm) % 9900
        street = self._pick(data.STREET_NAMES, "addr-s", norm)
        suffix = self._pick(data.STREET_SUFFIXES, "addr-x", norm)
        return _match_case(value.strip(), "%d %s %s" % (number, street, suffix))


class CityMasker(MethodChoiceMasker):
    type_name = "city"
    description = "Cities: method=realistic (fake city from a list, default) | hash | redact"

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
            if not tok.strip() or not tok[0].isalnum() or w in data.CONNECTOR_WORDS or w in data.PERSONAL_ENTITY_WORDS or (self.params["keep_industry_words"] and w in self._generic):
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
