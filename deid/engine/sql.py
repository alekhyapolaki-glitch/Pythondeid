"""SQL statements of the update: distinct-value reads, the #deid_map join update and key-range batches."""

from __future__ import annotations

from ..database.sql import hash_expr, quote_ident, text_expr
from .planner import ColumnPlan, TablePlan

MAP_MASKED_MAX = 4000


def key_expr(alias: str, cp: ColumnPlan) -> str:
    """Map key: hash of the value, or of (entity, value) for per-person maskers."""
    if cp.entity_info is None:
        return hash_expr(alias, cp.info)
    return "HASHBYTES('SHA2_256', CONCAT(ISNULL(N'1' + %s, N'0'), NCHAR(31), %s))" % (
        text_expr(alias, cp.entity_info), text_expr(alias, cp.info))


def distinct_values_sql(tp: TablePlan, cp: ColumnPlan) -> str:
    entity = (", MIN(%s) AS e" % text_expr("t", cp.entity_info)) if cp.entity_info is not None else ""
    return (
        "SELECT %s AS h, MIN(%s) AS v%s FROM %s AS t WHERE t.%s IS NOT NULL GROUP BY %s"  # nosec B608
        % (key_expr("t", cp), text_expr("t", cp.info), entity, tp.sql_name, quote_ident(cp.name), key_expr("t", cp))
    )


def update_sql(tp: TablePlan, ranged: bool, lower_bound: bool) -> str:
    sets, joins, conds = [], [], []
    for cp in tp.columns:
        qc = quote_ident(cp.name)
        if cp.is_nullify:
            sets.append("%s = NULL" % qc)
            conds.append("t.%s IS NOT NULL" % qc)
            continue
        a = "m%d" % cp.ordinal
        current = "t.%s" % qc
        if cp.info.data_type.lower() in ("text", "ntext"):
            current = "CAST(t.%s AS NVARCHAR(MAX))" % qc
        sets.append("%s = CASE WHEN %s.h IS NULL THEN %s ELSE %s.masked END" % (qc, a, current, a))
        joins.append("LEFT JOIN #deid_map AS %s ON %s.col_ord = %d AND %s.h = %s"
                     % (a, a, cp.ordinal, a, key_expr("t", cp)))
        conds.append("%s.h IS NOT NULL" % a)
    where = "(" + " OR ".join(conds) + ")"
    if ranged:
        qk = quote_ident(tp.key_columns[0])
        where += (" AND t.%s > ? AND t.%s <= ?" % (qk, qk)) if lower_bound else (" AND t.%s <= ?" % qk)
    return "UPDATE t SET %s FROM %s AS t %s WHERE %s" % (", ".join(sets), tp.sql_name, " ".join(joins), where)  # nosec B608


def chunk_bound_sql(tp: TablePlan, lower_bound: bool) -> str:
    qk = quote_ident(tp.key_columns[0])
    return "SELECT MAX(x.k) FROM (SELECT TOP (?) t.%s AS k FROM %s AS t %s ORDER BY t.%s) AS x" % (  # nosec B608
        qk, tp.sql_name, ("WHERE t.%s > ?" % qk) if lower_bound else "", qk)


MAP_DDL = (
    "IF OBJECT_ID('tempdb..#deid_map') IS NOT NULL DROP TABLE #deid_map; "
    "CREATE TABLE #deid_map (col_ord INT NOT NULL, h VARBINARY(32) NOT NULL, masked NVARCHAR(%d) NULL, "
    "PRIMARY KEY (col_ord, h));" % MAP_MASKED_MAX
)
