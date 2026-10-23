"""SQL text helpers. quote_ident() is the ONLY way identifiers enter SQL text; every data value is a
? parameter. text_expr/hash_expr give the canonical NVARCHAR form used for reading and joining."""

from __future__ import annotations

from .schema import ColumnInfo


def quote_ident(name: str) -> str:
    """Quote a SQL Server identifier: my]col -> [my]]col].

    This is the ONLY way identifiers enter SQL text in this tool; every data value is a ? parameter.
    """
    if not isinstance(name, str) or name == "":
        raise ValueError("Empty SQL identifier")
    if len(name) > 128 or "\x00" in name:
        raise ValueError("Invalid SQL identifier (longer than 128 characters or contains NUL)")
    return "[" + name.replace("]", "]]") + "]"


def qualified(schema: str, table: str) -> str:
    return "%s.%s" % (quote_ident(schema), quote_ident(table))


def text_expr(alias: str, col: ColumnInfo) -> str:
    """Canonical NVARCHAR text form of a column, identical in SELECT and UPDATE joins."""
    ref = "%s.%s" % (alias, quote_ident(col.name))
    t = col.data_type.lower()
    if t in ("datetime", "smalldatetime"):
        return "CONVERT(NVARCHAR(MAX), %s, 126)" % ref
    if t in ("money", "smallmoney"):
        return "CONVERT(NVARCHAR(MAX), %s, 2)" % ref
    return "CAST(%s AS NVARCHAR(MAX))" % ref


def hash_expr(alias: str, col: ColumnInfo) -> str:
    return "HASHBYTES('SHA2_256', %s)" % text_expr(alias, col)
