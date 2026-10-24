"""SQL of on-the-fly masking: SELECT from the source joined to #deid_map, and INSERT into the target.

Fail-safe: a non-NULL value without a mask-map entry (e.g. a row added to the source after the map was
built) makes the statement fail with a conversion error instead of copying the original value.  The
error text names no data.
"""

from __future__ import annotations

from typing import List

from ..database.sql import quote_ident
from .copy_plan import UDT_TYPES, CopyColumn, travels_as_text
from .planner import TablePlan
from .sql import MAP_MASKED_MAX, key_expr

UNMAPPED_MESSAGE = "deid: value missing from the mask map"
_FAILSAFE = "CAST(CAST(CONCAT(N'%s', LEFT(%%s.h, 0)) AS INT) AS NVARCHAR(%d))" % (UNMAPPED_MESSAGE, MAP_MASKED_MAX)

#: date/time types travel between servers as ISO 8601 text (style 126): exact (7 fractional digits,
#: UTC offset) and independent of the session language; the target converts it back
DATE_TEXT_LEN = 40


def _alias(cc: CopyColumn) -> str:
    return "m%d" % cc.masked.ordinal


def value_expr(cc: CopyColumn, stream: bool) -> str:
    ref = "t.%s" % quote_ident(cc.source.name)
    if cc.masked is not None:
        if cc.masked.is_nullify:
            return "NULL"
        a = _alias(cc)
        return "CASE WHEN %s IS NULL THEN NULL WHEN %s.h IS NULL THEN %s ELSE %s.masked END" % (
            ref, a, _FAILSAFE % a, a)
    if stream and travels_as_text(cc.source):
        return "CONVERT(NVARCHAR(%d), %s, 126)" % (DATE_TEXT_LEN, ref)
    if stream and cc.source.data_type.lower() in UDT_TYPES:
        return "CAST(%s AS VARBINARY(MAX))" % ref
    return ref


def _joins(tp: TablePlan) -> List[str]:
    return ["LEFT JOIN #deid_map AS %s ON %s.col_ord = %d AND %s.h = %s"
            % (_alias(c), _alias(c), c.masked.ordinal, _alias(c), key_expr("t", c.masked))
            for c in tp.target.columns if c.masked is not None and not c.masked.is_nullify]


def _range(tp: TablePlan, ranged: bool, lower_bound: bool) -> str:
    if not ranged:
        return ""
    qk = quote_ident(tp.key_columns[0])
    return (" WHERE t.%s > ? AND t.%s <= ?" % (qk, qk)) if lower_bound else (" WHERE t.%s <= ?" % qk)


def copy_select_sql(tp: TablePlan, stream: bool, ranged: bool, lower_bound: bool) -> str:
    """Masked rows of the source (one key range when ranged); streamed rows come in key order."""
    exprs = ", ".join(value_expr(c, stream) for c in tp.target.columns)
    sql = "SELECT %s FROM %s AS t %s%s" % (exprs, tp.sql_name, " ".join(_joins(tp)), _range(tp, ranged, lower_bound))  # nosec B608
    if stream and tp.key_columns:
        sql += " ORDER BY t.%s" % quote_ident(tp.key_columns[0])
    return sql


def _target_columns(tp: TablePlan) -> str:
    return ", ".join(quote_ident(c.target.name) for c in tp.target.columns)


def copy_insert_sql(tp: TablePlan, ranged: bool, lower_bound: bool) -> str:
    """Set-based: one INSERT...SELECT inside the instance (TABLOCK allows minimal logging)."""
    return "INSERT INTO %s WITH (TABLOCK) (%s) %s" % (  # nosec B608
        tp.target.full_name, _target_columns(tp), copy_select_sql(tp, False, ranged, lower_bound))


def stream_insert_sql(tp: TablePlan) -> str:
    """Streamed: parameterised INSERT on the target connection (fast_executemany)."""
    return "INSERT INTO %s WITH (TABLOCK) (%s) VALUES (%s)" % (  # nosec B608
        tp.target.sql_name, _target_columns(tp), ", ".join("?" for _ in tp.target.columns))


def identity_insert_sql(name: str, on: bool) -> str:
    return "SET IDENTITY_INSERT %s %s" % (name, "ON" if on else "OFF")
