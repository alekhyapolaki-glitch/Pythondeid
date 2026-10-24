"""Builds the de-identification plan: validates rules against the live schema, enforces FK domain
consistency, and chooses the update strategy and batch size per table."""

from __future__ import annotations

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

    @property
    def name(self) -> str:
        return self.info.name

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

    @property
    def ok(self) -> bool:
        return not self.errors

    def describe(self) -> str:
        lines = ["De-identification plan: %d table(s), %d column(s)" % (
            len(self.tables), sum(len(t.columns) for t in self.tables))]
        for tp in self.tables:
            size_mb = tp.info.data_bytes / 1048576.0
            if tp.strategy == "chunked":
                chunks = -(-tp.info.row_count // max(tp.batch_size, 1)) if tp.info.row_count else 0
                how = "chunked, %d rows/batch (~%d batches)" % (tp.batch_size, chunks)
            else:
                how = "single transaction, ~%d MB log" % estimate_log_mb(tp.info)
            lines.append("  %s  [~%d rows, %.1f MB, %s, key=%s]" % (
                tp.fqn, tp.info.row_count, size_mb, how, ",".join(tp.key_columns) or "-"))
            for cp in tp.columns:
                extra = []
                if cp.auto_added:
                    extra.append("auto-added via FK")
                if cp.entity_info is not None:
                    extra.append("per-person shift by %s" % cp.entity_info.name)
                if cp.output_info is not None:
                    extra.append("output_type %s" % cp.output_info.type_display())
                effective = dict(cp.domain.params, **cp.overrides)  # what this column will actually use
                for k in ("method", "mode"):
                    if k in effective:
                        extra.append("%s=%s%s" % (k, effective[k], " (this column)" if k in cp.overrides else ""))
                other = {k: v for k, v in cp.overrides.items() if k not in ("method", "mode")}
                if other:
                    extra.append(", ".join("%s=%s" % kv for kv in other.items()))
                lines.append("      - %-30s %-16s -> domain '%s' (%s)%s" % (
                    cp.name, cp.info.type_display(), cp.domain.name, cp.domain.type,
                    ("  [%s]" % "; ".join(extra)) if extra else ""))
            for ix in tp.disable_indexes:
                lines.append("      note: unique index %s disabled during update, rebuilt afterwards" % ix.name)
            for n in tp.notes:
                lines.append("      note: %s" % n)
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


def _identity_overrides(rule: Optional[ColumnRule], domain: str, rules: Rules) -> Dict[str, Any]:
    """Per-column settings that change the masked value (format-only overrides excluded)."""
    if rule is None or domain not in rules.domains:
        return {}
    cls = get_masker_class(rules.domains[domain].type)
    return {k: v for k, v in rule.overrides.items() if k in cls.column_params}


def build_plan(catalog: SchemaCatalog, rules: Rules, execution: Dict[str, Any], chunking_available: bool,
               batching: Optional[Dict[str, Any]] = None) -> Plan:
    errors: List[str] = []
    warnings: List[str] = []
    # (s,t) -> col_lower -> (domain, auto_added, ColumnRule or None)
    targets: Dict[Tuple[str, str], Dict[str, Tuple[str, bool, Optional[ColumnRule]]]] = {}
    order: List[Tuple[str, str]] = []
    key_override: Dict[Tuple[str, str], List[str]] = {}
    batching = batching or {}

    for tr in rules.tables:
        ti = catalog.get(tr.schema, tr.table)
        if ti is None:
            errors.append("Table %s does not exist (or is not visible to this login)" % tr.fqn)
            continue
        k = (ti.schema.lower(), ti.name.lower())
        order.append(k)
        targets[k] = {}
        key_override[k] = tr.key_columns
        for cr in tr.columns:
            if ti.column(cr.name) is None:
                errors.append("Column %s.%s does not exist" % (tr.fqn, cr.name))
                continue
            targets[k][cr.name.lower()] = (cr.domain, False, cr)

    # ---- referential integrity closure over foreign keys --------------------
    fks: Dict[Tuple[str, str], ForeignKey] = {}
    queue = [(k, c) for k in order for c in list(targets[k])]
    while queue:
        (s, t), c = queue.pop(0)
        domain = targets[(s, t)][c][0]
        for fk, _side, os_, ot, oc in catalog.fks_touching(s, t, c):
            fks[(fk.schema.lower(), fk.name.lower())] = fk
            if fk.update_action == 1:
                errors.append(
                    "FK %s (%s -> %s) is ON UPDATE CASCADE on masked column %s; cascading would double-mask the "
                    "child. Change the FK to NO ACTION for the masking run." % (fk.name, fk.child_fqn, fk.parent_fqn, c))
            ok_key = (os_.lower(), ot.lower())
            other = targets.get(ok_key, {}).get(oc.lower())
            src_rule = targets[(s, t)][c][2]
            if other is not None:
                if other[0] != domain:
                    errors.append(
                        "FK %s links %s.%s.%s (domain '%s') and %s.%s.%s (domain '%s'); both sides must use the same "
                        "domain or the relationship breaks." % (fk.name, s, t, c, domain, os_, ot, oc, other[0]))
                elif _identity_overrides(src_rule, domain, rules) != _identity_overrides(other[2], domain, rules):
                    errors.append(
                        "FK %s links %s.%s.%s and %s.%s.%s with different per-column settings (e.g. method); both "
                        "sides must mask identically." % (fk.name, s, t, c, os_, ot, oc))
                continue
            if execution.get("auto_include_fk_columns", True) and catalog.get(os_, ot) is not None:
                if ok_key not in targets:
                    targets[ok_key] = {}
                    order.append(ok_key)
                    key_override[ok_key] = []
                inherited = _identity_overrides(src_rule, domain, rules)
                partner_rule = ColumnRule(oc, domain, overrides=inherited) if inherited else None
                targets[ok_key][oc.lower()] = (domain, True, partner_rule)
                queue.append((ok_key, oc.lower()))
                warnings.append("Auto-added %s.%s.%s (domain '%s') because FK %s references masked column %s.%s.%s"
                                % (os_, ot, oc, domain, fk.name, s, t, c))
            else:
                errors.append(
                    "FK %s links masked column %s.%s.%s to %s.%s.%s which is not masked; add it with domain '%s' "
                    "(or enable execution.auto_include_fk_columns)." % (fk.name, s, t, c, os_, ot, oc, domain))

    # ---- per table checks and strategy ------------------------------------
    tables: List[TablePlan] = []
    domain_families: Dict[str, set] = {}
    mismatch = execution.get("type_mismatch", "error")
    for k in order:
        ti = catalog.get(*k)
        cols: List[ColumnPlan] = []
        for ordinal, (cname, (dname, auto, rule)) in enumerate(targets[k].items(), start=1):
            ci = ti.column(cname)
            dom = rules.domains.get(dname)
            if dom is None:
                errors.append("Domain '%s' used by %s.%s is not defined" % (dname, ti.fqn, ci.name))
                continue
            cls = get_masker_class(dom.type)
            where = "%s.%s (%s)" % (ti.fqn, ci.name, ci.type_display())
            if ci.is_computed:
                errors.append("%s is a computed column and cannot be updated; mask its source columns" % where)
            if ci.is_identity:
                errors.append("%s is an IDENTITY column and cannot be updated" % where)
            if ci.family not in cls.families:
                errors.append("%s: mask type '%s' supports %s columns only" % (where, dom.type, "/".join(cls.families)))
            if dom.type == "nullify" and not ci.is_nullable:
                errors.append("%s is NOT NULL; it cannot be nullified" % where)
            col_params = dict(dom.params, **(rule.overrides if rule is not None else {}))
            if ti.is_unique_column(ci.name) and not is_injective(dom.type, col_params):
                errors.append("%s is part of a primary key/unique index but '%s' is not collision-free; use an "
                              "injective type (fpe, account_number, ssn, email, hash, ...)" % (where, dom.type))
            cp = ColumnPlan(ci, dom, ordinal, auto)
            if rule is not None:
                cp.overrides = dict(rule.overrides)
                cp.expected_input_type = rule.expected_input_type
                if rule.expected_input_type:
                    try:
                        if not same_type(rule.expected_input_type, ci):
                            msg = ("%s: expected_input_type is %s but the live column is %s"
                                   % (where, rule.expected_input_type, ci.type_display()))
                            (errors if mismatch == "error" else warnings).append(msg)
                    except ValueError as exc:
                        errors.append("%s: %s" % (where, exc))
                if rule.output_type:
                    try:
                        cp.output_info = parse_type(rule.output_type, ci.name, ci.is_nullable)
                    except ValueError as exc:
                        errors.append("%s: %s" % (where, exc))
                    else:
                        if cp.output_info.family != ci.family and cls is not get_masker_class("nullify"):
                            warnings.append("%s: output_type %s is a different type family than the column; values "
                                            "are validated against both" % (where, rule.output_type))
                if rule.entity_column:
                    ei = ti.column(rule.entity_column)
                    if ei is None:
                        errors.append("%s: entity_column %s does not exist in %s" % (where, rule.entity_column, ti.fqn))
                    elif ei.family == "other":
                        errors.append("%s: entity_column %s has unsupported type %s" % (where, ei.name, ei.data_type))
                    else:
                        cp.entity_info = ei
            elif cls.entity_required(cls.validate_params(dom.params)):
                errors.append("%s was auto-added with per-person date domain '%s' but has no entity_column; add it "
                              "to the rules explicitly" % (where, dname))
            domain_families.setdefault(dname, set()).add(ci.family)
            cols.append(cp)

        tp = TablePlan(ti, cols)
        masked = {c.name.lower() for c in cols}
        key = key_override.get(k) or ti.primary_key
        if not key:
            for us in ti.unique_sets:
                if all(ti.column(c) and not ti.column(c).is_nullable for c in us) and not masked & {c.lower() for c in us}:
                    key = us
                    break
        for kc in key:
            if ti.column(kc) is None:
                errors.append("%s: key column %s does not exist" % (ti.fqn, kc))
        tp.key_columns = [ti.column(kc).name for kc in key if ti.column(kc) is not None]

        reasons = []
        if not chunking_available:
            reasons.append("audit.write_to_db is off (checkpoints need it)")
        if len(tp.key_columns) != 1:
            reasons.append("no single-column key" if not tp.key_columns else "composite key")
        elif tp.key_columns[0].lower() in masked:
            reasons.append("key column is masked")
        elif tp.key_info.family not in ("int", "string"):
            reasons.append("key type %s not supported for chunking" % tp.key_info.data_type)
        blocking, disable = [], []
        for c in cols:
            for ix in ti.unique_indexes_on(c.name):
                if ix.can_disable and execution.get("disable_unique_indexes", True):
                    if ix not in disable:
                        disable.append(ix)
                else:
                    blocking.append("%s (%s)" % (c.name, ix.name))
        if blocking:
            reasons.append("masked column(s) %s are in a PK/clustered/FK-referenced unique index" % ", ".join(blocking))
        if reasons:
            tp.strategy = "single"
            tp.notes.append("single-statement update: " + "; ".join(reasons))
            limit = execution.get("allow_single_statement_rows", 50000000)
            if ti.row_count > limit:
                warnings.append("%s has ~%d rows and will be updated in ONE transaction (~%d MB log) because %s. "
                                "Make sure the log can hold it, or provide an unmasked key_columns."
                                % (ti.fqn, ti.row_count, estimate_log_mb(ti), "; ".join(reasons)))
        else:
            tp.strategy = "chunked"
            tp.disable_indexes = disable
            bs = execution.get("batch_size", "auto")
            tp.batch_size = recommend_batch_size(ti, batching) if bs == "auto" else int(bs)
        tables.append(tp)

    for dname, fams in domain_families.items():
        dom = rules.domains.get(dname)
        normalized = dom is not None and (dom.params.get("normalize") == "digits" or dom.type == "ssn")
        if len(fams) > 1 and not normalized:
            warnings.append("Domain '%s' is used on columns of different type families %s; values only stay "
                            "consistent where their text form is identical (e.g. '00123' vs 123 differ). "
                            "Use params {normalize: digits, pad_to: N} (see 'recommend')." % (dname, sorted(fams)))
    return Plan(tables, list(fks.values()), warnings, errors)
