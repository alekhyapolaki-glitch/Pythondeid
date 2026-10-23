"""Checks that a masked value fits its target column type (length, numeric range, precision, dates)."""

from __future__ import annotations

import decimal
from typing import Optional

from ..database.schema import INT_RANGES, ColumnInfo
from .sql import MAP_MASKED_MAX


def check_fits(col: ColumnInfo, masked: Optional[str]) -> Optional[str]:
    if masked is None:
        return None if col.is_nullable else "masked value is NULL but column is NOT NULL"
    if len(masked) > MAP_MASKED_MAX:
        return "masked value longer than %d characters is not supported" % MAP_MASKED_MAX
    fam = col.family
    if fam == "string":
        mc = col.max_chars
        if mc and mc > 0 and len(masked) > mc:
            return "masked value length %d exceeds %s" % (len(masked), col.type_display())
    elif fam == "int":
        try:
            n = int(masked)
        except ValueError:
            return "masked value is not an integer (%s)" % col.type_display()
        lo, hi = INT_RANGES[col.data_type.lower()]
        if not lo <= n <= hi:
            return "masked value is out of %s range" % col.data_type
    elif fam == "decimal":
        try:
            d = decimal.Decimal(masked)
        except decimal.InvalidOperation:
            return "masked value is not numeric (%s)" % col.type_display()
        if col.data_type.lower() in ("decimal", "numeric"):
            int_digits = len(str(abs(int(d)))) if int(d) != 0 else 0
            if int_digits > col.precision - col.scale:
                return "masked value exceeds %s(%d,%d)" % (col.data_type, col.precision, col.scale)
    elif fam == "date":
        try:
            year = int(masked.strip()[:4])
        except ValueError:
            return "masked value is not a date"
        t = col.data_type.lower()
        if (t == "datetime" and year < 1753) or (t == "smalldatetime" and not 1900 <= year <= 2079):
            return "masked date is outside the %s range" % t
    return None
