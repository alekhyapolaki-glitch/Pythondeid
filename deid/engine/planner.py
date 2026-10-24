"""Builds the de-identification plan: validates rules against the live schema, enforces FK domain
consistency, and chooses the update strategy and batch size per table."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from ..advisor import estimate_log_mb, recommend_batch_size
from ..config import ColumnRule, DomainRule, Rules
from ..database.schema import ColumnInfo, ForeignKey, IndexInfo, SchemaCatalog, TableInfo, parse_type, same_type
from ..database.sql import qualified
from ..masking import get_masker_class, is_injective


class PlanError(Exception):
    pass


@dataclass
class ColumnPlan:
    info: ColumnInfo
    domain: DomainRule
    ordinal: int
    auto_added: bool = False
    entity_info: Optional[ColumnInfo] = None
    output_info: Optional[ColumnInfo] = None
    overrides: Dict[str, Any] = field(default_factory=dict)
    expected_input_type: str = ""
    #: on-the-fly masking: the column the masked value is written to (None = in place)
    target_info: Optional[ColumnInfo] = None

    @property
    def name(self) -> str:
        return self.info.name

    @property
    def fit_targets(self) -> List[ColumnInfo]:
        """Columns every masked value must fit: where it is written (+ the rule's output_type)."""
        return [self.target_info or self.info] + ([self.output_info] if self.output_info is not None else [])

    @property
    def is_nullify(self) -> bool:
        return self.domain.type == "nullify"


@dataclass
class TablePlan:
    info: TableInfo
    columns: List[ColumnPlan]
    key_columns: List[str] = field(default_factory=list)
    strategy: str = "single"
    batch_size: int = 0
    disable_indexes: List[IndexInfo] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    #: on-the-fly masking: where and how the table is written (copy_plan.CopyTarget)
    target: Optional[Any] = None

    @property
    def fqn(self) -> str:
        return self.info.fqn

    @property
    def sql_name(self) -> str:
        return qualified(self.info.schema, self.info.name)

    @property
    def key_info(self) -> Optional[ColumnInfo]:
        return self.info.column(self.key_columns[0]) if self.key_columns else None


@dataclass
class Plan:
    tables: List[TablePlan]
    foreign_keys: List[ForeignKey]
    warnings: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    mode: str = "in_place"
    #: on-the-fly masking: target connection, transfer method, target FKs (copy_plan.CopySetup)
    copy: Optional[Any] = None

    @property
    def ok(self) -> bool:
        return not self.errors

    def describe(self) -> str:
        lines = ["De-identification plan (%s): %d table(s), %d masked column(s)" % (
            self.mode, len(self.tables), sum(len(t.columns) for t in self.tables))]
        if self.copy is not None:
            lines.extend(self.copy.header_lines())
        for tp in self.tables:
            size_mb = tp.info.data_bytes / 1048576.0
            if tp.strategy == "chunked":
                chunks = -(-tp.info.row_count // max(tp.batch_size, 1)) if tp.info.row_count else 0
                how = "chunked, %d rows/batch (~%d batches)" % (tp.batch_size, chunks)
            else:
                how = "single transaction, ~%d MB log" % estimate_log_mb(tp.info)
            lines.append("  %s%s  [~%d rows, %.1f MB, %s, key=%s]" % (
                tp.fqn, (" -> %s" % tp.target.describe()) if tp.target is not None else "",
                tp.info.row_count, size_mb, how, ",".join(tp.key_columns) or "-"))
            lines.extend(_column_line(cp) for cp in tp.columns)
            for ix in tp.disable_indexes:
                lines.append("      note: unique index %s disabled during update, rebuilt afterwards" % ix.name)
            for n in tp.notes:
                lines.append("      note: %s" % n)
            if tp.target is not None:
                lines.extend(tp.target.detail_lines())
        if self.foreign_keys:
            lines.append("  Foreign keys toggled during the run:")
            for fk in self.foreign_keys:
                lines.append("      - %s on %s -> %s%s" % (
                    fk.name, fk.child_fqn, fk.parent_fqn, " (currently disabled)" if fk.is_disabled else ""))
        for w in self.warnings:
            lines.append("WARNING: " + w)
        for e in self.errors:
            lines.append("ERROR:   " + e)
        return "\n".join(lines)


def _column_line(cp: ColumnPlan) -> str:
    extra = []
    if cp.auto_added:
        extra.append("auto-added via FK")
    if cp.entity_info is not None:
        extra.append("per-person shift by %s" % cp.entity_info.name)
    if cp.target_info is not None and cp.target_info.name != cp.name:
        extra.append("written to %s" % cp.target_info.name)
    if cp.output_info is not None:
        extra.append("output_type %s" % cp.output_info.type_display())
    effective = dict(cp.domain.params, **cp.overrides)  # what this column will actually use
    for k in ("method", "mode"):
        if k in effective:
            extra.append("%s=%s%s" % (k, effective[k], " (this column)" if k in cp.overrides else ""))
    other = {k: v for k, v in cp.overrides.items() if k not in ("method", "mode")}
    if other:
        extra.append(", ".join("%s=%s" % kv for kv in other.items()))
    return "      - %-30s %-16s -> domain '%s' (%s)%s" % (
        cp.name, cp.info.type_display(), cp.domain.name, cp.domain.type,
        ("  [%s]" % "; ".join(extra)) if extra else "")


def _identity_overrides(rule: Optional[ColumnRule], domain: str, rules: Rules) -> Dict[str, Any]:
    """Per-column settings that change the masked value (format-only overrides excluded)."""
    if rule is None or domain not in rules.domains:
        return {}
    cls = get_masker_class(rules.domains[domain].type)
    return {k: v for k, v in rule.overrides.items() if k in cls.column_params}


# (schema, table) lower-case -> column lower-case -> (domain, auto_added, ColumnRule or None)
_Targets = Dict[Tuple[str, str], Dict[str, Tuple[str, bool, Optional[ColumnRule]]]]


def build_plan(catalog: SchemaCatalog, rules: Rules, execution: Dict[str, Any], chunking_available: bool,
               batching: Optional[Dict[str, Any]] = None, mode: str = "in_place") -> Plan:
    """Validate the rules against the live (source) schema and decide how each table is processed.

    mode=on_the_fly: the source is only read, so update-only checks (cascading FKs, unique indexes on
    masked columns, masked chunk keys) do not apply, and FK partners are only masked when their table
    is copied too; copy_plan then maps every table onto the target.
    """
    return _Planner(catalog, rules, execution, chunking_available, batching or {}, mode).build()


class _Planner:
    """One planning run. Steps: resolve targets -> FK closure -> per-column checks -> key + strategy."""

    def __init__(self, catalog, rules, execution, chunking_available, batching, mode="in_place"):
        self.catalog, self.rules, self.execution = catalog, rules, execution
        self.mode = mode
        self.copy_mode = mode == "on_the_fly"
        self.chunking_available, self.batching = chunking_available, batching
        self.errors: List[str] = []
        self.warnings: List[str] = []
        self.targets: _Targets = {}
        self.order: List[Tuple[str, str]] = []
        self.key_override: Dict[Tuple[str, str], List[str]] = {}
        self.fks: Dict[Tuple[str, str], ForeignKey] = {}
        self.domain_families: Dict[str, set] = {}

    def build(self) -> Plan:
        self._resolve_targets()
        self._close_over_foreign_keys()
        tables = [self._plan_table(k) for k in self.order]
        self._warn_mixed_type_domains()
        # on the fly, the source FKs are never touched (copy_plan toggles the target's)
        fks = [] if self.copy_mode else list(self.fks.values())
        return Plan(tables, fks, self.warnings, self.errors, self.mode)

    # ---- step 1: tables and columns named in the rules ----------------------
    def _resolve_targets(self) -> None:
        for tr in self.rules.tables:
            ti = self.catalog.get(tr.schema, tr.table)
            if ti is None:
                self.errors.append("Table %s does not exist (or is not visible to this login)" % tr.fqn)
                continue
            k = (ti.schema.lower(), ti.name.lower())
            self.order.append(k)
            self.targets[k] = {}
            self.key_override[k] = tr.key_columns
            for cr in tr.columns:
                if ti.column(cr.name) is None:
                    self.errors.append("Column %s.%s does not exist" % (tr.fqn, cr.name))
                    continue
                self.targets[k][cr.name.lower()] = (cr.domain, False, cr)

    # ---- step 2: referential integrity closure over foreign keys ------------
    def _close_over_foreign_keys(self) -> None:
        queue = deque((k, c) for k in self.order for c in list(self.targets[k]))
        while queue:
            (s, t), c = queue.popleft()
            domain, _, src_rule = self.targets[(s, t)][c]
            for fk, _side, os_, ot, oc in self.catalog.fks_touching(s, t, c):
                self.fks[(fk.schema.lower(), fk.name.lower())] = fk
                if fk.update_action == 1 and not self.copy_mode:
                    self.errors.append(
                        "FK %s (%s -> %s) is ON UPDATE CASCADE on masked column %s; cascading would double-mask the "
                        "child. Change the FK to NO ACTION for the masking run." % (fk.name, fk.child_fqn, fk.parent_fqn, c))
                other_key = (os_.lower(), ot.lower())
                other = self.targets.get(other_key, {}).get(oc.lower())
                if other is not None:
                    self._check_fk_pair(fk, (s, t, c), (os_, ot, oc), domain, src_rule, other)
                elif self.copy_mode and other_key not in self.targets:
                    continue  # that table is not copied, so its values are never written anywhere
                elif self.execution.get("auto_include_fk_columns", True) and self.catalog.get(os_, ot) is not None:
                    self._auto_add_partner(fk, (s, t, c), (os_, ot, oc), domain, src_rule)
                    queue.append((other_key, oc.lower()))
                else:
                    self.errors.append(
                        "FK %s links masked column %s.%s.%s to %s.%s.%s which is not masked; add it with domain '%s' "
                        "(or enable execution.auto_include_fk_columns)." % (fk.name, s, t, c, os_, ot, oc, domain))

    def _check_fk_pair(self, fk, here, there, domain, src_rule, other) -> None:
        (s, t, c), (os_, ot, oc) = here, there
        if other[0] != domain:
            self.errors.append(
                "FK %s links %s.%s.%s (domain '%s') and %s.%s.%s (domain '%s'); both sides must use the same "
                "domain or the relationship breaks." % (fk.name, s, t, c, domain, os_, ot, oc, other[0]))
        elif _identity_overrides(src_rule, domain, self.rules) != _identity_overrides(other[2], domain, self.rules):
            self.errors.append(
                "FK %s links %s.%s.%s and %s.%s.%s with different per-column settings (e.g. method); both "
                "sides must mask identically." % (fk.name, s, t, c, os_, ot, oc))

    def _auto_add_partner(self, fk, here, there, domain, src_rule) -> None:
        (s, t, c), (os_, ot, oc) = here, there
        other_key = (os_.lower(), ot.lower())
        if other_key not in self.targets:
            self.targets[other_key] = {}
            self.order.append(other_key)
            self.key_override[other_key] = []
        inherited = _identity_overrides(src_rule, domain, self.rules)
        partner_rule = ColumnRule(oc, domain, overrides=inherited) if inherited else None
        self.targets[other_key][oc.lower()] = (domain, True, partner_rule)
        self.warnings.append("Auto-added %s.%s.%s (domain '%s') because FK %s references masked column %s.%s.%s"
                             % (os_, ot, oc, domain, fk.name, s, t, c))

    # ---- step 3: per table: columns, key, strategy ---------------------------
    def _plan_table(self, k: Tuple[str, str]) -> TablePlan:
        ti = self.catalog.get(*k)
        cols = []
        for ordinal, (cname, (dname, auto, rule)) in enumerate(self.targets[k].items(), start=1):
            cp = self._plan_column(ti, ti.column(cname), dname, auto, rule, ordinal)
            if cp is not None:
                cols.append(cp)
        tp = TablePlan(ti, cols)
        tp.key_columns = self._choose_key(k, ti, {c.name.lower() for c in cols})
        self._choose_strategy(tp)
        return tp

    def _plan_column(self, ti: TableInfo, ci: ColumnInfo, dname: str, auto: bool, rule: Optional[ColumnRule],
                     ordinal: int) -> Optional[ColumnPlan]:
        dom = self.rules.domains.get(dname)
        if dom is None:
            self.errors.append("Domain '%s' used by %s.%s is not defined" % (dname, ti.fqn, ci.name))
            return None
        cls = get_masker_class(dom.type)
        where = "%s.%s (%s)" % (ti.fqn, ci.name, ci.type_display())
        self._check_column_type(ti, ci, dom, cls, rule, where)
        cp = ColumnPlan(ci, dom, ordinal, auto)
        if rule is not None:
            self._apply_column_rule(ti, ci, cls, rule, cp, where)
        elif cls.entity_required(cls.validate_params(dom.params)):
            self.errors.append("%s was auto-added with per-person date domain '%s' but has no entity_column; add it "
                               "to the rules explicitly" % (where, dname))
        self.domain_families.setdefault(dname, set()).add(ci.family)
        return cp

    def _check_column_type(self, ti, ci, dom, cls, rule, where) -> None:
        if ci.is_computed:
            self.errors.append("%s is a computed column and cannot be updated; mask its source columns" % where)
        if ci.is_identity:
            self.errors.append("%s is an IDENTITY column and cannot be updated" % where)
        if ci.family not in cls.families:
            self.errors.append("%s: mask type '%s' supports %s columns only" % (where, dom.type, "/".join(cls.families)))
        if dom.type == "nullify" and not ci.is_nullable:
            self.errors.append("%s is NOT NULL; it cannot be nullified" % where)
        col_params = dict(dom.params, **(rule.overrides if rule is not None else {}))
        if ti.is_unique_column(ci.name) and not is_injective(dom.type, col_params):
            self.errors.append("%s is part of a primary key/unique index but '%s' is not collision-free; use an "
                               "injective type (fpe, account_number, ssn, email, hash, ...)" % (where, dom.type))

    def _apply_column_rule(self, ti, ci, cls, rule: ColumnRule, cp: ColumnPlan, where: str) -> None:
        cp.overrides = dict(rule.overrides)
        cp.expected_input_type = rule.expected_input_type
        if rule.expected_input_type:
            try:
                if not same_type(rule.expected_input_type, ci):
                    msg = ("%s: expected_input_type is %s but the live column is %s"
                           % (where, rule.expected_input_type, ci.type_display()))
                    (self.errors if self.execution.get("type_mismatch", "error") == "error" else self.warnings).append(msg)
            except ValueError as exc:
                self.errors.append("%s: %s" % (where, exc))
        if rule.output_type:
            try:
                cp.output_info = parse_type(rule.output_type, ci.name, ci.is_nullable)
            except ValueError as exc:
                self.errors.append("%s: %s" % (where, exc))
            else:
                if cp.output_info.family != ci.family and cls is not get_masker_class("nullify"):
                    self.warnings.append("%s: output_type %s is a different type family than the column; values "
                                         "are validated against both" % (where, rule.output_type))
        if rule.entity_column:
            ei = ti.column(rule.entity_column)
            if ei is None:
                self.errors.append("%s: entity_column %s does not exist in %s" % (where, rule.entity_column, ti.fqn))
            elif ei.family == "other":
                self.errors.append("%s: entity_column %s has unsupported type %s" % (where, ei.name, ei.data_type))
            else:
                cp.entity_info = ei

    def _choose_key(self, k, ti: TableInfo, masked: set) -> List[str]:
        key = self.key_override.get(k) or ti.primary_key
        if not key:
            for us in ti.unique_sets:
                if all(ti.column(c) and not ti.column(c).is_nullable for c in us) and not masked & {c.lower() for c in us}:
                    key = us
                    break
        for kc in key:
            if ti.column(kc) is None:
                self.errors.append("%s: key column %s does not exist" % (ti.fqn, kc))
        return [ti.column(kc).name for kc in key if ti.column(kc) is not None]

    def _choose_strategy(self, tp: TablePlan) -> None:
        ti, masked = tp.info, {c.name.lower() for c in tp.columns}
        reasons = []
        if not self.chunking_available:
            reasons.append("audit.write_to_db is off (checkpoints need it)")
        if len(tp.key_columns) != 1:
            reasons.append("no single-column key" if not tp.key_columns else "composite key")
        elif tp.key_columns[0].lower() in masked and not self.copy_mode:
            reasons.append("key column is masked")  # on the fly the key is only read from the source
        elif tp.key_info.family not in ("int", "string"):
            reasons.append("key type %s not supported for chunking" % tp.key_info.data_type)
        blocking, disable = [], []
        for c in ([] if self.copy_mode else tp.columns):  # the source's own indexes matter only in place
            for ix in ti.unique_indexes_on(c.name):
                if ix.can_disable and self.execution.get("disable_unique_indexes", True):
                    if ix not in disable:
                        disable.append(ix)
                else:
                    blocking.append("%s (%s)" % (c.name, ix.name))
        if blocking:
            reasons.append("masked column(s) %s are in a PK/clustered/FK-referenced unique index" % ", ".join(blocking))
        if reasons:
            tp.strategy = "single"
            verb = "copied" if self.copy_mode else "updated"
            tp.notes.append("single-statement %s: %s" % ("copy" if self.copy_mode else "update", "; ".join(reasons)))
            if ti.row_count > self.execution.get("allow_single_statement_rows", 50000000):
                self.warnings.append(
                    "%s has ~%d rows and will be %s in ONE transaction (~%d MB log) because %s. "
                    "Make sure the log can hold it, or provide key_columns."
                    % (ti.fqn, ti.row_count, verb, estimate_log_mb(ti), "; ".join(reasons)))
        else:
            tp.strategy = "chunked"
            tp.disable_indexes = disable
            bs = self.execution.get("batch_size", "auto")
            tp.batch_size = recommend_batch_size(ti, self.batching) if bs == "auto" else int(bs)

    # ---- step 4: consistency warnings across the whole plan -----------------
    def _warn_mixed_type_domains(self) -> None:
        for dname, fams in self.domain_families.items():
            dom = self.rules.domains.get(dname)
            normalized = dom is not None and (dom.params.get("normalize") == "digits" or dom.type == "ssn")
            if len(fams) > 1 and not normalized:
                self.warnings.append(
                    "Domain '%s' is used on columns of different type families %s; values only stay "
                    "consistent where their text form is identical (e.g. '00123' vs 123 differ). "
                    "Use params {normalize: digits, pad_to: N} (see 'recommend')." % (dname, sorted(fams)))
