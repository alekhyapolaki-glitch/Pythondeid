"""Reads dates written as text in common layouts and writes a new date back in exactly the same layout.

Keeps: separators (- / .), zero padding of each part, 2/4-digit order (Y-M-D, M/D/Y or D/M/Y),
English month names (abbreviated or full, upper/lower/title case), a time-of-day or timezone suffix,
and leading/trailing spaces.  Real SQL date/datetime columns and Excel date cells are converted to
ISO text by the caller and written back as dates, so they stay dates.

Supported layouts (examples for 12 April 1980):
    1980-04-12   1980/04/12   1980.04.12   1980-4-12   19800412
    04/12/1980   4/12/1980    04-12-1980   04.12.1980        (day_first=True: 12/04/1980)
    12-Apr-1980  12 Apr 1980  12-APRIL-1980                   Apr 12 1980   April 12, 1980
    any of the above followed by a time / timezone: 1980-04-12T10:15:00.123, 04/12/1980 10:15 AM
"""

from __future__ import annotations

import datetime as _dt
import re
from typing import Callable, Tuple

from .base import MaskerError

MONTHS = ("january", "february", "march", "april", "may", "june", "july", "august", "september", "october",
          "november", "december")
_MONTH_LOOKUP = {**{m: i + 1 for i, m in enumerate(MONTHS)}, **{m[:3]: i + 1 for i, m in enumerate(MONTHS)},
                 "sept": 9}

# the date part must end at the end of the text or before a time/space ('T' or whitespace)
_END = r"(?=$|[Tt\s])"
_YMD = re.compile(r"^(\s*)(\d{4})([-/.])(\d{1,2})\3(\d{1,2})" + _END + r"(.*)$", re.S)
_NUMERIC_YEAR_LAST = re.compile(r"^(\s*)(\d{1,2})([-/.])(\d{1,2})\3(\d{4})" + _END + r"(.*)$", re.S)
_COMPACT = re.compile(r"^(\s*)(\d{4})(\d{2})(\d{2})(\s*)$")
_DAY_MONTHNAME_YEAR = re.compile(r"^(\s*)(\d{1,2})([-\s])([A-Za-z]{3,9})\.?\3(\d{4})" + _END + r"(.*)$", re.S)
_MONTHNAME_DAY_YEAR = re.compile(r"^(\s*)([A-Za-z]{3,9})\.?(\s+)(\d{1,2})(,?\s+)(\d{4})" + _END + r"(.*)$", re.S)

Renderer = Callable[[_dt.date], str]


def _num(original: str, value: int) -> str:
    """Zero-pad like the original part: '04' -> 2 digits, '4' -> as is."""
    return "%02d" % value if len(original) == 2 else str(value)


def _month_name(original: str, month: int) -> str:
    full = MONTHS[month - 1]
    name = full if len(original) > 4 and original.lower() in MONTHS else full[:3]
    if original.isupper():
        return name.upper()
    if original.islower():
        return name
    return name.capitalize()


def _month_number(token: str) -> int:
    m = _MONTH_LOOKUP.get(token.lower())
    if m is None:
        raise MaskerError("Unrecognised month name")
    return m


def parse_date_text(value: str, day_first: bool = False) -> Tuple[_dt.date, str, Renderer]:
    """Returns (date, rest after the date part, renderer that writes another date in the same layout)."""
    m = _YMD.match(value)
    if m:
        lead, y, sep, mo, d, rest = m.groups()
        return _dt.date(int(y), int(mo), int(d)), rest, (
            lambda n: "%s%04d%s%s%s%s" % (lead, n.year, sep, _num(mo, n.month), sep, _num(d, n.day)))
    m = _NUMERIC_YEAR_LAST.match(value)
    if m:
        lead, a, sep, b, y, rest = m.groups()
        if day_first:
            date = _dt.date(int(y), int(b), int(a))
            return date, rest, (lambda n: "%s%s%s%s%s%04d" % (lead, _num(a, n.day), sep, _num(b, n.month), sep, n.year))
        date = _dt.date(int(y), int(a), int(b))
        return date, rest, (lambda n: "%s%s%s%s%s%04d" % (lead, _num(a, n.month), sep, _num(b, n.day), sep, n.year))
    m = _COMPACT.match(value)
    if m:
        lead, y, mo, d, rest = m.groups()
        return _dt.date(int(y), int(mo), int(d)), rest, (lambda n: "%s%s" % (lead, n.strftime("%Y%m%d")))
    m = _DAY_MONTHNAME_YEAR.match(value)
    if m:
        lead, d, sep, mon, y, rest = m.groups()
        dot = "." if value[m.end(4):m.end(4) + 1] == "." else ""
        return _dt.date(int(y), _month_number(mon), int(d)), rest, (
            lambda n: "%s%s%s%s%s%s%04d" % (lead, _num(d, n.day), sep, _month_name(mon, n.month), dot, sep, n.year))
    m = _MONTHNAME_DAY_YEAR.match(value)
    if m:
        lead, mon, sp, d, comma, y, rest = m.groups()
        dot = "." if value[m.end(2):m.end(2) + 1] == "." else ""
        return _dt.date(int(y), _month_number(mon), int(d)), rest, (
            lambda n: "%s%s%s%s%s%s%04d" % (lead, _month_name(mon, n.month), dot, sp, _num(d, n.day), comma, n.year))
    raise MaskerError("Unrecognised date format (supported: YYYY-MM-DD, MM/DD/YYYY, DD-Mon-YYYY, "
                      "Month DD, YYYY, YYYYMMDD and variants with / - . separators)")
