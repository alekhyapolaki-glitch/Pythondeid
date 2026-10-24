"""Reads table structure, keys, unique indexes, foreign keys and triggers from SQL Server catalog views."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Tuple

STRING_TYPES = {"char", "varchar", "nchar", "nvarchar", "text", "ntext"}
INT_TYPES = {"tinyint", "smallint", "int", "bigint"}
DECIMAL_TYPES = {"decimal", "numeric", "money", "smallmoney"}
DATE_TYPES = {"date", "datetime", "datetime2", "smalldatetime", "datetimeoffset"}

INT_RANGES = {
    "tinyint": (0, 255),
    "smallint": (-32768, 32767),
    "int": (-2147483648, 2147483647),
    "bigint": (-9223372036854775808, 9223372036854775807),
}


@dataclass
class ColumnInfo:
    schema: str
    table: str
    name: str
    data_type: str
    max_length: int
    precision: int
    scale: int
    is_nullable: bool
    is_computed: bool = False
    is_identity: bool = False
    column_id: int = 0

    @property
    def family(self) -> str:
        t = self.data_type.lower()
        if t in STRING_TYPES:
            return "string"
        if t in INT_TYPES:
            return "int"
        if t in DECIMAL_TYPES:
            return "decimal"
        if t in DATE_TYPES:
            return "date"
        return "other"

    @property
    def max_chars(self) -> Optional[int]:
        """Character capacity for string columns; -1 for MAX types; None otherwise."""
        t = self.data_type.lower()
        if t in ("text", "ntext") or self.max_length == -1:
            return -1 if t in STRING_TYPES else None
        if t in ("nchar", "nvarchar"):
            return self.max_length // 2
        if t in ("char", "varchar"):
            return self.max_length
        return None

    def type_display(self) -> str:
        t = self.data_type.lower()
        if t in ("char", "varchar", "nchar", "nvarchar"):
            return "%s(%s)" % (t, "max" if self.max_chars == -1 else self.max_chars)
        if t in ("decimal", "numeric"):
            return "%s(%d,%d)" % (t, self.precision, self.scale)
        return t


_TYPE_RE = re.compile(r"^\s*([a-z0-9_]+)\s*(?:\(\s*(max|\d+)\s*(?:,\s*(\d+)\s*)?\))?\s*$", re.I)


def parse_type(text: str, name: str = "output", nullable: bool = True) -> ColumnInfo:
    """'varchar(11)' / 'nvarchar(max)' / 'decimal(12,2)' / 'int' -> ColumnInfo (max_length in bytes, like sys.columns)."""
    m = _TYPE_RE.match(text or "")
    if not m:
        raise ValueError("Cannot parse SQL type '%s' (examples: varchar(11), nvarchar(max), decimal(12,2), int)" % text)
    base, size, scale = m.group(1).lower(), m.group(2), m.group(3)
    known = STRING_TYPES | INT_TYPES | DECIMAL_TYPES | DATE_TYPES | {"float", "real", "uniqueidentifier", "bit"}
    if base not in known:
        raise ValueError("Unknown SQL type '%s'" % base)
    max_length, precision, sc = 0, 0, 0
    if base in ("char", "varchar", "nchar", "nvarchar"):
        n = -1 if (size or "").lower() == "max" else int(size or 1)
        max_length = n * 2 if base in ("nchar", "nvarchar") and n != -1 else n
    elif base in ("text", "ntext"):
        max_length = -1
    elif base in ("decimal", "numeric"):
        precision, sc = int(size or 18), int(scale or 0)
    return ColumnInfo("", "", name, base, max_length, precision, sc, nullable)


def same_type(expected: str, actual: ColumnInfo) -> bool:
    exp = parse_type(expected)
    if exp.data_type != actual.data_type.lower():
        return False
    if exp.family == "string":
        return exp.max_chars == actual.max_chars
    if exp.data_type in ("decimal", "numeric"):
        return (exp.precision, exp.scale) == (actual.precision, actual.scale)
    return True


@dataclass
class IndexInfo:
    name: str
    columns: List[str]
    is_primary_key: bool = False
    is_clustered: bool = False
    is_disabled: bool = False
    referenced_by_fk: bool = False

    @property
    def can_disable(self) -> bool:
        """Nonclustered, not a PK and not the target of a foreign key -> safe to disable and rebuild."""
        return not (self.is_primary_key or self.is_clustered or self.referenced_by_fk)


@dataclass
class TableInfo:
    schema: str
    name: str
    columns: Dict[str, ColumnInfo] = field(default_factory=dict)  # keyed by lower-case name
    primary_key: List[str] = field(default_factory=list)
    unique_sets: List[List[str]] = field(default_factory=list)
    row_count: int = 0
    unique_indexes: List[IndexInfo] = field(default_factory=list)
    data_bytes: int = 0      # used pages of heap/clustered index (incl. LOB) * 8 KB

    @property
    def avg_row_bytes(self) -> int:
        return max(1, self.data_bytes // self.row_count) if self.row_count and self.data_bytes else 200

    def unique_indexes_on(self, column: str) -> List[IndexInfo]:
        c = column.lower()
        return [i for i in self.unique_indexes if c in [x.lower() for x in i.columns]]

    @property
    def fqn(self) -> str:
        return "%s.%s" % (self.schema, self.name)

    def column(self, name: str) -> Optional[ColumnInfo]:
        return self.columns.get(name.lower())

    def ordered_columns(self) -> List[ColumnInfo]:
        return sorted(self.columns.values(), key=lambda c: c.column_id)

    def is_unique_column(self, name: str) -> bool:
        n = name.lower()
        return any(n in [c.lower() for c in s] for s in self.unique_sets)


@dataclass
class ForeignKey:
    name: str
    schema: str          # referencing (child) table
    table: str
    ref_schema: str      # referenced (parent) table
    ref_table: str
    column_pairs: List[Tuple[str, str]]  # (child column, parent column)
    update_action: int = 0               # 0 = NO ACTION, 1 = CASCADE, 2 = SET NULL, 3 = SET DEFAULT
    is_disabled: bool = False

    @property
    def child_fqn(self) -> str:
        return "%s.%s" % (self.schema, self.table)

    @property
    def parent_fqn(self) -> str:
        return "%s.%s" % (self.ref_schema, self.ref_table)


def _key(schema: str, table: str) -> Tuple[str, str]:
    return schema.lower(), table.lower()


@dataclass
class SchemaCatalog:
    tables: Dict[Tuple[str, str], TableInfo] = field(default_factory=dict)
    foreign_keys: List[ForeignKey] = field(default_factory=list)

    def get(self, schema: str, table: str) -> Optional[TableInfo]:
        return self.tables.get(_key(schema, table))

    def add_table(self, t: TableInfo) -> None:
        self.tables[_key(t.schema, t.name)] = t

    def fks_touching(self, schema: str, table: str, column: str) -> Iterable[Tuple[ForeignKey, str, str, str, str]]:
        """Yield (fk, this_side, other_schema, other_table, other_column) for FKs involving the column."""
        s, t, c = schema.lower(), table.lower(), column.lower()
        for fk in self.foreign_keys:
            for child_col, parent_col in fk.column_pairs:
                if (fk.schema.lower(), fk.table.lower(), child_col.lower()) == (s, t, c):
                    yield fk, "child", fk.ref_schema, fk.ref_table, parent_col
                if (fk.ref_schema.lower(), fk.ref_table.lower(), parent_col.lower()) == (s, t, c):
                    yield fk, "parent", fk.schema, fk.table, child_col

    # ------------------------------------------------------------------ loading
    @classmethod
    def load(cls, conn, schemas: Optional[List[str]] = None) -> SchemaCatalog:
        cat = cls()
        cur = conn.cursor()
        # Static SQL only; the optional schema filter is applied in Python (catalog views are small).
        wanted = {x.lower() for x in schemas} if schemas else None

        def keep(schema_name: str) -> bool:
            return wanted is None or schema_name.lower() in wanted

        cur.execute(
            """
            SELECT s.name, t.name, c.name, TYPE_NAME(c.system_type_id), c.max_length, c.precision, c.scale,
                   c.is_nullable, c.is_computed, c.is_identity, c.column_id
            FROM sys.tables t
            JOIN sys.schemas s ON s.schema_id = t.schema_id
            JOIN sys.columns c ON c.object_id = t.object_id
            WHERE t.is_ms_shipped = 0
            ORDER BY s.name, t.name, c.column_id"""
        )
        for row in cur.fetchall():
            if not keep(row[0]):
                continue
            t = cat.get(row[0], row[1])
            if t is None:
                t = TableInfo(row[0], row[1])
                cat.add_table(t)
            t.columns[row[2].lower()] = ColumnInfo(
                row[0], row[1], row[2], row[3], int(row[4]), int(row[5]), int(row[6]),
                bool(row[7]), bool(row[8]), bool(row[9]), int(row[10]),
            )

        cur.execute(
            """
            SELECT s.name, t.name, i.name, i.is_primary_key, c.name, i.type, i.is_disabled,
                   CASE WHEN EXISTS (SELECT 1 FROM sys.foreign_keys fk WHERE fk.referenced_object_id = i.object_id
                                     AND fk.key_index_id = i.index_id) THEN 1 ELSE 0 END
            FROM sys.indexes i
            JOIN sys.tables t ON t.object_id = i.object_id
            JOIN sys.schemas s ON s.schema_id = t.schema_id
            JOIN sys.index_columns ic ON ic.object_id = i.object_id AND ic.index_id = i.index_id
            JOIN sys.columns c ON c.object_id = ic.object_id AND c.column_id = ic.column_id
            WHERE i.is_unique = 1 AND ic.is_included_column = 0
            ORDER BY s.name, t.name, i.index_id, ic.key_ordinal"""
        )
        sets: Dict[Tuple[str, str, str], IndexInfo] = {}
        for schema, table, index, is_pk, col, itype, is_dis, ref in cur.fetchall():
            ix = sets.get((schema, table, index))
            if ix is None:
                ix = IndexInfo(index, [], bool(is_pk), int(itype) == 1, bool(is_dis), bool(ref))
                sets[(schema, table, index)] = ix
            ix.columns.append(col)
        for (schema, table, _), ix in sets.items():
            t = cat.get(schema, table)
            if t is None:
                continue
            t.unique_sets.append(list(ix.columns))
            t.unique_indexes.append(ix)
            if ix.is_primary_key:
                t.primary_key = list(ix.columns)

        cur.execute(
            """
            SELECT s.name, t.name, SUM(p.rows),
                   (SELECT SUM(a.used_pages) FROM sys.partitions p2
                    JOIN sys.allocation_units a ON a.container_id = p2.partition_id
                    WHERE p2.object_id = t.object_id AND p2.index_id IN (0, 1))
            FROM sys.tables t
            JOIN sys.schemas s ON s.schema_id = t.schema_id
            JOIN sys.partitions p ON p.object_id = t.object_id AND p.index_id IN (0, 1)
            GROUP BY s.name, t.name, t.object_id"""
        )
        for schema, table, rows, pages in cur.fetchall():
            t = cat.get(schema, table)
            if t is not None:
                t.row_count = int(rows or 0)
                t.data_bytes = int(pages or 0) * 8192

        # Foreign keys are always loaded database-wide: a referencing table may live in another schema.
        cur.execute(
            """
            SELECT fk.name, cs.name, ct.name, cc.name, ps.name, pt.name, pc.name,
                   fk.update_referential_action, fk.is_disabled, fkc.constraint_column_id
            FROM sys.foreign_keys fk
            JOIN sys.foreign_key_columns fkc ON fkc.constraint_object_id = fk.object_id
            JOIN sys.tables ct ON ct.object_id = fk.parent_object_id
            JOIN sys.schemas cs ON cs.schema_id = ct.schema_id
            JOIN sys.columns cc ON cc.object_id = fkc.parent_object_id AND cc.column_id = fkc.parent_column_id
            JOIN sys.tables pt ON pt.object_id = fk.referenced_object_id
            JOIN sys.schemas ps ON ps.schema_id = pt.schema_id
            JOIN sys.columns pc ON pc.object_id = fkc.referenced_object_id AND pc.column_id = fkc.referenced_column_id
            ORDER BY fk.name, fkc.constraint_column_id"""
        )
        fks: Dict[Tuple[str, str], ForeignKey] = {}
        for name, cs, ct, cc, ps, pt, pc, upd, dis, _ in cur.fetchall():
            fk = fks.get((cs, name))
            if fk is None:
                fk = ForeignKey(name, cs, ct, ps, pt, [], int(upd), bool(dis))
                fks[(cs, name)] = fk
            fk.column_pairs.append((cc, pc))
        cat.foreign_keys = list(fks.values())
        return cat


def enabled_triggers(conn, schema: str, table: str) -> List[str]:
    cur = conn.cursor()
    cur.execute(
        """
        SELECT tr.name FROM sys.triggers tr
        JOIN sys.tables t ON t.object_id = tr.parent_id
        JOIN sys.schemas s ON s.schema_id = t.schema_id
        WHERE s.name = ? AND t.name = ? AND tr.is_disabled = 0""",
        [schema, table],
    )
    return [r[0] for r in cur.fetchall()]


def fk_status(conn, schema: str, name: str) -> Tuple[bool, bool]:
    """Returns (is_disabled, is_not_trusted) for a foreign key."""
    cur = conn.cursor()
    cur.execute(
        "SELECT fk.is_disabled, fk.is_not_trusted FROM sys.foreign_keys fk "
        "JOIN sys.schemas s ON s.schema_id = fk.schema_id WHERE s.name = ? AND fk.name = ?",
        [schema, name],
    )
    row = cur.fetchone()
    return (bool(row[0]), bool(row[1])) if row else (False, False)


def index_disabled(conn, schema: str, table: str, index: str) -> bool:
    cur = conn.cursor()
    cur.execute(
        "SELECT i.is_disabled FROM sys.indexes i JOIN sys.tables t ON t.object_id = i.object_id "
        "JOIN sys.schemas s ON s.schema_id = t.schema_id WHERE s.name = ? AND t.name = ? AND i.name = ?",
        [schema, table, index],
    )
    row = cur.fetchone()
    return bool(row[0]) if row else False
