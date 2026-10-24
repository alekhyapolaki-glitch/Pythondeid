"""On-the-fly masking plan: maps every planned source table onto its target table (copy_map.yaml) and
checks that the pre-created target is ready before anything is written:

* target table and mapped columns exist; types match (same schema expected)
* every target column that is not written is nullable, has a default, or is generated
* the target is not the source table itself
* foreign keys: target FKs touching the copied tables are toggled for the load; a target table that is
  NOT copied but references a reloaded table must be empty (its rows would be orphaned)
* transfer: set_based (INSERT...SELECT inside one SQL Server instance) or stream (rows read from the
  source, already masked, written over a second connection)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from ..config import CopyMap
from ..database.schema import ColumnInfo, ForeignKey, SchemaCatalog, TableInfo
from ..database.sql import qualified, quote_ident
from .planner import ColumnPlan, Plan, TablePlan

#: SQL Server reports rowversion as 'timestamp'; the target generates it
GENERATED_TYPES = {"timestamp"}
#: CLR types: moved as their binary form (implicitly converted back by the target)
UDT_TYPES = {"geography", "geometry", "hierarchyid"}
#: types pyodbc cannot read, so they can only be copied inside one SQL Server instance
NOT_STREAMABLE = {"sql_variant"}


def travels_as_text(ci: ColumnInfo) -> bool:
    """Date/time values are streamed as ISO 8601 text: Python's datetime/time hold only microseconds, SQL
    Server keeps 100 ns (and datetimeoffset a UTC offset), so text is the only exact route."""
    return ci.family == "date" or ci.data_type.lower() == "time"


@dataclass
class CopyColumn:
    source: ColumnInfo
    target: ColumnInfo
    masked: Optional[ColumnPlan] = None   # None = copied as it is


@dataclass
class CopyTarget:
    info: TableInfo
    columns: List[CopyColumn]
    identity_insert: bool = False         # a target IDENTITY column is written (SET IDENTITY_INSERT)
    referenced_by_fk: bool = False        # TRUNCATE is not allowed: emptied with batched DELETEs
    existing_rows: int = 0
    db_prefix: str = ""                   # "[TargetDb]." for set-based (three-part names)

    @property
    def sql_name(self) -> str:
        """Name on the target connection."""
        return qualified(self.info.schema, self.info.name)

    @property
    def full_name(self) -> str:
        """Name as seen from the source session (set-based transfer)."""
        return self.db_prefix + self.sql_name

    def describe(self) -> str:
        return self.info.fqn

    def detail_lines(self) -> List[str]:
        renamed = ["%s->%s" % (c.source.name, c.target.name) for c in self.columns if c.source.name != c.target.name]
        as_is = sum(1 for c in self.columns if c.masked is None)
        lines = ["      copy: %d column(s) written (%d masked, %d as-is)%s" % (
            len(self.columns), len(self.columns) - as_is, as_is,
            "; renamed %s" % ", ".join(renamed) if renamed else "")]
        if self.existing_rows:
            lines.append("      note: target has ~%d row(s); emptied first (%s)" % (
                self.existing_rows, "batched DELETE: referenced by a foreign key" if self.referenced_by_fk
                else "TRUNCATE"))
        if self.identity_insert:
            lines.append("      note: IDENTITY values copied from the source (SET IDENTITY_INSERT)")
        return lines


@dataclass
class CopySetup:
    target_connection: str
    target_server: str
    target_database: str
    transfer: str                         # set_based | stream
    on_existing_rows: str
    disable_nonclustered_indexes: bool
    foreign_keys: List[ForeignKey] = field(default_factory=list)

    def header_lines(self) -> List[str]:
        how = ("set-based INSERT...SELECT inside the SQL Server instance" if self.transfer == "set_based"
               else "streamed: read from the source, masked, written to the target")
        return ["  Source is only read. Target: %s / %s (connection '%s'); transfer: %s" % (
            self.target_server, self.target_database, self.target_connection, how),
            "  Existing target rows: %s; %d target foreign key(s) off during the load, then validated WITH CHECK"
            % ("emptied first" if self.on_existing_rows == "truncate" else "not allowed (on_existing_rows: error)",
               len(self.foreign_keys))]


def build_copy_plan(plan: Plan, copy_map: CopyMap, target: SchemaCatalog, *, same_instance: bool,
                    source_database: str, target_server: str, target_database: str,
                    target_connection: str) -> None:
    """Attach a CopyTarget to every table and a CopySetup to the plan; problems go to plan.errors."""
    transfer = copy_map.transfer
    if transfer == "auto":
        transfer = "set_based" if same_instance else "stream"
    elif transfer == "set_based" and not same_instance:
        plan.errors.append("copy_map transfer: set_based needs the target on the same SQL Server instance as the "
                           "source; use transfer: auto or stream")
    plan.copy = CopySetup(target_connection, target_server, target_database, transfer, copy_map.on_existing_rows,
                          copy_map.disable_nonclustered_indexes)
    same_db = same_instance and source_database.lower() == target_database.lower()
    sources = {tp.fqn.lower() for tp in plan.tables}
    written: Dict[str, str] = {}
    for tp in plan.tables:
        tgt = _map_table(plan, tp, copy_map, target, same_db)
        if tgt is None:
            continue
        key = tgt.info.fqn.lower()
        if key in written:
            plan.errors.append("%s and %s are both written to target %s" % (written[key], tp.fqn, tgt.info.fqn))
        elif same_db and key in sources:
            plan.errors.append("Target %s (for %s) is itself a source table of this copy; it would be emptied "
                               "before it is read" % (tgt.info.fqn, tp.fqn))
        written[key] = tp.fqn
        tp.target = tgt
    _plan_target_fks(plan, target, set(written))
    if copy_map.on_existing_rows == "error":
        busy = ["%s (~%d rows)" % (tp.target.info.fqn, tp.target.existing_rows)
                for tp in plan.tables if tp.target is not None and tp.target.existing_rows]
        if busy:
            plan.errors.append("Target table(s) are not empty and on_existing_rows is 'error': %s" % ", ".join(busy))
    set_transfer(plan, transfer)


def set_transfer(plan: Plan, transfer: str) -> None:
    """Fix the transfer method; streaming cannot carry every type, and set-based needs three-part names."""
    plan.copy.transfer = transfer
    prefix = quote_ident(plan.copy.target_database) + "." if transfer == "set_based" else ""
    for tp in plan.tables:
        if tp.target is None:
            continue
        tp.target.db_prefix = prefix
        if transfer == "stream":
            for c in tp.target.columns:
                if c.masked is None and c.source.data_type.lower() in NOT_STREAMABLE:
                    plan.errors.append(
                        "%s.%s is %s, which cannot be streamed between servers; copy inside one instance "
                        "(transfer: set_based) or leave the column out (copy_map columns)"
                        % (tp.fqn, c.source.name, c.source.data_type))


def _copyable(ci: ColumnInfo) -> bool:
    return not ci.is_computed and ci.data_type.lower() not in GENERATED_TYPES


def _map_table(plan: Plan, tp: TablePlan, copy_map: CopyMap, target: SchemaCatalog,
               same_db: bool) -> Optional[CopyTarget]:
    m = copy_map.mapping(tp.info.schema, tp.info.name)
    tti = target.get(m.target_schema, m.target_table)
    if tti is None:
        plan.errors.append("Target table %s (for %s) does not exist; the target schema must be created first "
                           "(e.g. SqlPackage/DACPAC or generated scripts)" % (m.target_fqn, tp.fqn))
        return None
    if same_db and tti.fqn.lower() == tp.fqn.lower():
        plan.errors.append("%s: the target is the source table itself; map it to another table or database "
                           "(copy_map.yaml) or use execution.mode: in_place" % tp.fqn)
        return None
    sources = _source_columns(plan, tp, m.columns)
    masked = {cp.name.lower(): cp for cp in tp.columns}
    copied = {c.name.lower() for c in sources}
    for name in [n for n in masked if n not in copied]:
        plan.warnings.append("%s.%s is masked in the rules but not copied (copy_map columns); it is skipped"
                             % (tp.fqn, masked[name].name))
        tp.columns.remove(masked.pop(name))
    cols: List[CopyColumn] = []
    for sc in sources:
        tc = tti.column(m.target_column(sc.name))
        where = "%s.%s -> %s.%s" % (tp.fqn, sc.name, tti.fqn, m.target_column(sc.name))
        if tc is None:
            plan.errors.append("%s: target column does not exist (map it with column_map)" % where)
            continue
        if not _copyable(tc):
            plan.errors.append("%s: target column is computed/rowversion and cannot be written" % where)
            continue
        cp = masked.get(sc.name.lower())
        if cp is not None:
            cp.target_info = tc
            if cp.is_nullify and not tc.is_nullable:
                plan.errors.append("%s: target column is NOT NULL; it cannot be nullified" % where)
        else:
            _check_as_is(plan, sc, tc, where)
        cols.append(CopyColumn(sc, tc, cp))
    _check_unwritten(plan, tti, {c.target.name.lower() for c in cols})
    return CopyTarget(
        tti, cols, identity_insert=any(c.target.is_identity for c in cols),
        referenced_by_fk=any(_same(fk.ref_schema, fk.ref_table, tti) for fk in target.foreign_keys),
        existing_rows=tti.row_count)


def _source_columns(plan: Plan, tp: TablePlan, wanted) -> List[ColumnInfo]:
    """Source columns to copy, in source column order."""
    all_cols = [c for c in tp.info.ordered_columns() if _copyable(c)]
    if wanted == "all":
        return all_cols
    names = {w.lower() for w in wanted}
    for w in wanted:
        ci = tp.info.column(w)
        if ci is None:
            plan.errors.append("copy_map: %s has no column %s" % (tp.fqn, w))
        elif not _copyable(ci):
            plan.errors.append("copy_map: %s.%s is computed/rowversion; the target computes it" % (tp.fqn, w))
    return [c for c in all_cols if c.name.lower() in names]


def _check_as_is(plan: Plan, sc: ColumnInfo, tc: ColumnInfo, where: str) -> None:
    """A column copied unmasked must keep its type (the target schema matches the source)."""
    if sc.family != tc.family or (sc.family == "other" and sc.data_type.lower() != tc.data_type.lower()):
        plan.errors.append("%s: type differs (%s -> %s)" % (where, sc.type_display(), tc.type_display()))
        return
    narrower = (sc.family == "string" and tc.max_chars not in (None, -1)
                and (sc.max_chars == -1 or (sc.max_chars or 0) > tc.max_chars))
    if sc.family == "decimal" and sc.data_type.lower() in ("decimal", "numeric"):
        narrower = narrower or (tc.precision - tc.scale) < (sc.precision - sc.scale) or tc.scale < sc.scale
    if narrower:
        plan.warnings.append("%s: target type %s is narrower than %s; longer values fail the load"
                             % (where, tc.type_display(), sc.type_display()))
    if sc.is_nullable and not tc.is_nullable:
        plan.warnings.append("%s: target is NOT NULL but the source allows NULL; NULL rows fail the load" % where)


def _check_unwritten(plan: Plan, tti: TableInfo, written: set) -> None:
    for tc in tti.ordered_columns():
        if tc.name.lower() in written or tc.is_nullable or tc.has_default or tc.is_identity or not _copyable(tc):
            continue
        plan.errors.append("Target column %s.%s is NOT NULL without a default and nothing is written to it "
                           "(add it to the copied columns or column_map)" % (tti.fqn, tc.name))


def _same(schema: str, table: str, ti: TableInfo) -> bool:
    return (schema.lower(), table.lower()) == (ti.schema.lower(), ti.name.lower())


def _plan_target_fks(plan: Plan, target: SchemaCatalog, loaded: set) -> None:
    """Toggle every target FK touching a reloaded table; refuse to orphan rows of tables not copied."""
    for fk in target.foreign_keys:
        child, parent = fk.child_fqn.lower() in loaded, fk.parent_fqn.lower() in loaded
        if not (child or parent):
            continue
        plan.copy.foreign_keys.append(fk)
        if parent and not child:
            ct = target.get(fk.schema, fk.table)
            if ct is not None and ct.row_count:
                plan.errors.append(
                    "Target table %s is not copied but has ~%d row(s) referencing %s (FK %s), which is emptied and "
                    "reloaded; empty %s first or add its source table to the rules"
                    % (fk.child_fqn, ct.row_count, fk.parent_fqn, fk.name, fk.child_fqn))
        elif child and not parent:
            plan.warnings.append("Target %s references %s (FK %s), which is not copied: the target must already "
                                 "hold the referenced rows (checked WITH CHECK after the load)"
                                 % (fk.child_fqn, fk.parent_fqn, fk.name))
