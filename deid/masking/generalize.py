"""Generalisation and suppression: ZIP truncation, date shifting (per value or per person), redact, nullify."""

from __future__ import annotations

import datetime as _dt
import re

from .base import BaseMasker, MaskerError, _choice, _non_negative_int
from .fpe import FeistelCipher, encrypt_text


# HIPAA Safe Harbor (45 CFR 164.514(b)(2)(i)(B)): the initial three ZIP digits may be kept only if the
# area they cover has more than 20,000 people; HHS lists these 3-digit areas (2000 Census) as having
# 20,000 or fewer, so they must become 000.  Review against current HHS guidance before relying on it.
HIPAA_RESTRICTED_ZIP3 = frozenset({
    "036", "059", "063", "102", "203", "556", "692", "790", "821", "823", "830", "831", "878", "879", "884",
    "890", "893",
})


class ZipMasker(BaseMasker):
    type_name = "zip"
    description = ("ZIP/postal: mode=truncate keeps the first N digits; mode=hipaa keeps 3 and zeroes the HIPAA "
                   "low-population areas; mode=fpe is bijective")
    default_params = {"mode": "truncate", "keep_digits": 3, "fill": "0"}
    families = ("string", "int")

    @classmethod
    def _check_params(cls, p):
        _choice(p, "mode", ("truncate", "hipaa", "fpe"))
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
        keep = self.params["keep_digits"]
        if self.params["mode"] == "hipaa":
            digits = re.sub(r"\D", "", value)
            keep = 0 if digits[:3] in HIPAA_RESTRICTED_ZIP3 else 3
        seen = 0
        out = []
        for ch in value:
            if ch.isdigit():
                out.append(ch if seen < keep else self.params["fill"])
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
    default_params = {"max_days": 365, "generalize": "none", "shift_by": "value", "entity_normalize": "trim_lower",
                      "birth_date": False, "reference_year": 0}
    #: a column marks itself as a birth date; same domain (and per-person offset) as the person's other dates
    column_params = frozenset({"birth_date"})
    families = ("string", "date")
    uses_entity = True

    @classmethod
    def _check_params(cls, p):
        if not isinstance(p["max_days"], int) or isinstance(p["max_days"], bool) or p["max_days"] < 1:
            raise MaskerError("date_shift.max_days must be a positive integer")
        _choice(p, "generalize", ("none", "year", "month"))
        _choice(p, "shift_by", ("value", "entity"))
        _choice(p, "entity_normalize", ("none", "trim_lower", "digits"))
        if not isinstance(p["birth_date"], bool):
            raise MaskerError("date_shift.birth_date must be true or false")
        if not isinstance(p["reference_year"], int) or p["reference_year"] < 0:
            raise MaskerError("date_shift.reference_year must be 0 (current year) or a year")

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
        except MaskerError:
            raise
        except ValueError as exc:
            # Never include the value itself (errors end up in logs and audit files). datetime's own
            # messages, e.g. "month must be in 1..12", describe the problem without the data.
            raise MaskerError("Invalid date: %s" % exc) from None
        gen = self.params["generalize"]
        if gen in ("year", "month") and self.params["birth_date"]:
            # Safe Harbor: ages over 89 (and birth years revealing them) are grouped as "90 or older".
            ref = self.params["reference_year"] or _dt.date.today().year
            if ref - date.year >= 90:
                date = _dt.date(ref - 90, 1, 1)
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
