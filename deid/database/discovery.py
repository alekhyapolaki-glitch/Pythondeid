"""Column name heuristics, schema export to CSV, and the interactive rules wizard."""

from __future__ import annotations

import csv
import re
from typing import Dict, List, Optional

from ..config import CSV_COLUMNS, ColumnRule, DomainRule, Rules, TableRule
from ..masking import MASKERS, get_masker_class
from ..utils import prompts
from ..masking.suggestions import suggest_type
from .schema import ColumnInfo, SchemaCatalog, TableInfo


def export_schema_csv(catalog: SchemaCatalog, path: str, only_suggested: bool = False) -> int:
    """Write table structure + suggested masks to CSV for review/editing (mask_type left for the user)."""
    rows = 0
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=CSV_COLUMNS)
        w.writeheader()
        for (_, _), t in sorted(catalog.tables.items()):
            pk = {c.lower() for c in t.primary_key}
            for c in t.ordered_columns():
                sug = suggest_type(c) or ""
                if only_suggested and not sug:
                    continue
                w.writerow({
                    "schema": t.schema, "table": t.name, "column": c.name, "data_type": c.type_display(),
                    "max_length": c.max_chars if c.max_chars is not None else "", "is_nullable": int(c.is_nullable),
                    "is_primary_key": int(c.name.lower() in pk), "suggested_type": sug,
                    "mask_type": "", "domain": "", "params_json": "",
                    "expected_input_type": c.type_display(), "output_type": "", "entity_column": "",
                })
                rows += 1
    return rows


# =============================================================================
# Interactive wizard
# =============================================================================
def _print_table(t: TableInfo) -> None:
    pk = {c.lower() for c in t.primary_key}
    print("\n  %s  (~%d rows)" % (t.fqn, t.row_count))
    print("  %-4s %-32s %-18s %-5s %-4s %s" % ("#", "column", "type", "null", "pk", "suggestion"))
    for i, c in enumerate(t.ordered_columns(), start=1):
        print("  %-4d %-32s %-18s %-5s %-4s %s" % (
            i, c.name, c.type_display(), "yes" if c.is_nullable else "no",
            "pk" if c.name.lower() in pk else "", suggest_type(c) or ""))


def run_wizard(catalog: SchemaCatalog, existing: Optional[Rules] = None,
               policy: Optional[Dict[str, str]] = None) -> Rules:
    print("\n=== De-identification rules wizard ===")
    print("Answer the questions below; press Enter to accept the [default].\n")
    domains: Dict[str, DomainRule] = dict(existing.domains) if existing else {}
    tables: List[TableRule] = []
    for t in _choose_tables(catalog):
        rule = _ask_table(t, domains, policy or {})
        if rule is not None:
            tables.append(rule)
    if existing:
        kept = [et for et in existing.tables if et.fqn.lower() not in {x.fqn.lower() for x in tables}]
        if kept and prompts.ask_yes_no("Keep %d table(s) from the existing rules file?" % len(kept), True):
            tables = kept + tables
    used = {c.domain for t in tables for c in t.columns}
    rules = Rules({k: v for k, v in domains.items() if k in used}, tables)
    if policy:
        rules.policy = dict(policy)
    rules.content_hash = rules.compute_hash()
    return rules


def _choose_tables(catalog: SchemaCatalog) -> List[TableInfo]:
    schemas = sorted({t.schema for t in catalog.tables.values()})
    chosen_schemas = prompts.choose_many("Which schemas contain data to de-identify?", schemas, "all")
    candidates = sorted((t for t in catalog.tables.values() if t.schema in chosen_schemas), key=lambda t: t.fqn)
    if not candidates:
        raise SystemExit("No tables found in the chosen schemas.")
    flagged = [t.fqn for t in candidates if any(suggest_type(c) for c in t.columns.values())]
    print("\nTables with likely PII columns: %s" % (", ".join(flagged) or "none detected"))
    names = [t.fqn for t in candidates]
    default_sel = ",".join(str(names.index(n) + 1) for n in flagged) if flagged else "all"
    selected = prompts.choose_many("Which tables should be de-identified?", names, default_sel)
    by_name = {t.fqn: t for t in candidates}
    return [by_name[n] for n in selected]


def _ask_table(t: TableInfo, domains: Dict[str, DomainRule], policy: Dict[str, str]) -> Optional[TableRule]:
    _print_table(t)
    cols = [r for r in (_ask_column(t, c, domains, policy) for c in t.ordered_columns()
                        if not (c.is_identity or c.is_computed)) if r is not None]
    if not cols:
        return None
    key_cols: List[str] = []
    if not t.primary_key:
        print("  %s has no primary key." % t.fqn)
        raw = prompts.ask("  Optional unique NOT NULL key column(s) for batched updates (comma separated)",
                          "", required=False)
        key_cols = [k.strip() for k in raw.split(",") if k.strip()]
    return TableRule(t.schema, t.name, cols, key_cols)


def _ask_column(t: TableInfo, c: ColumnInfo, domains: Dict[str, DomainRule],
                policy: Dict[str, str]) -> Optional[ColumnRule]:
    sug = suggest_type(c)
    if not prompts.ask_yes_no("  Mask %s.%s (%s)?" % (t.name, c.name, c.type_display()), default=bool(sug)):
        return None
    allowed = [m for m in sorted(MASKERS) if c.family in get_masker_class(m).families]
    print("    Mask types for this column:")
    mtype = prompts.choose("    Mask type", allowed, sug if sug in allowed else allowed[0])
    dom = _choose_domain(c, mtype, domains)
    rule = ColumnRule(c.name, dom.name, expected_input_type=c.type_display())
    if dom.params.get("shift_by") == "entity":
        rule.entity_column = _ask_entity_column(t, c)
    _ask_column_overrides(rule, c, dom, policy)
    rule.output_type = prompts.ask("    Expected OUTPUT data type (Enter = same as column %s)" % c.type_display(),
                                   "", required=False)
    return rule


def _choose_domain(c: ColumnInfo, mtype: str, domains: Dict[str, DomainRule]) -> DomainRule:
    """Pick (or create) the domain; a new one gets its key questions and optional parameters."""
    print("    A *domain* ties columns together: the same value in the same domain is masked identically in "
          "every table (needed for joins/FKs).")
    same_type = [d for d in domains.values() if d.type == mtype]
    dname = prompts.ask("    Domain name", same_type[0].name if same_type else mtype)
    if dname not in domains:
        params = _ask_key_questions(mtype, c, domains)
        params.update(_ask_params(mtype, skip=set(params)))
        domains[dname] = DomainRule(dname, mtype, params)
    elif domains[dname].type != mtype:
        print("    Domain '%s' is already a '%s' domain; using that definition." % (dname, domains[dname].type))
    return domains[dname]


_PERSON_ID = re.compile(r"(person|patient|customer|member|employee|client|subject).*id$")


def _ask_entity_column(t: TableInfo, c: ColumnInfo) -> str:
    others = [x.name for x in t.ordered_columns() if x.name != c.name and x.family != "other"]
    pk = {k.lower() for k in t.primary_key}
    candidates = [x for x in others if x.lower() not in pk]
    default = next((x for x in candidates if _PERSON_ID.search(x.lower())),
                   next((x for x in candidates if x.lower().endswith("id")), others[0]))
    return prompts.choose("    Which column identifies the person in %s?" % t.name, others, default)


def _ask_column_overrides(rule: ColumnRule, c: ColumnInfo, dom: DomainRule, policy: Dict[str, str]) -> None:
    """Per-column settings: output format (SSN/account/card) and method (names, address, city)."""
    cls = get_masker_class(dom.type)
    if "output_format" in cls.format_params and prompts.ask_yes_no(
            "    Use a different output format for this column?", False):
        opts = ["preserve", "dashed", "digits"] if dom.type == "ssn" else ["preserve", "digits", "grouped"]
        rule.overrides["output_format"] = prompts.choose("    Output format", opts, "preserve")
    if "method" in cls.column_params:
        policy_key = {"street_address": "address", "city": "city"}.get(dom.type, "names")
        default_method = policy.get(policy_key, "realistic")
        print("    realistic = fake values | hash = unique code | redact = constant")
        chosen = prompts.choose("    Method for %s (policy default: %s)" % (c.name, default_method),
                                ["realistic", "hash", "redact"], default_method)
        if chosen != default_method:
            rule.overrides["method"] = chosen


def _ask_key_questions(mtype: str, col: ColumnInfo, domains: Dict[str, DomainRule]) -> Dict[str, object]:
    """The decisions that matter most per type, asked in plain language."""
    p: Dict[str, object] = {}
    if mtype in ("account_number", "fpe") and prompts.ask_yes_no(
            "    Is this identifier stored as a NUMBER in some tables and as text/zero-padded in others?",
            col.family in ("int", "decimal")):
        p["normalize"] = "digits"
        p["pad_to"] = prompts.ask_int("    Maximum number of digits the identifier can have", 12, 1)
    if mtype == "date_shift":
        if prompts.ask_yes_no("    Shift all dates of the same person by the same offset (keeps intervals)?", True):
            p["shift_by"] = "entity"
        p["max_days"] = prompts.ask_int("    Maximum shift in days (+/-)", 365, 1)
    if mtype == "free_text":
        p["mode"] = prompts.choose("    Free text handling", ["scrub", "redact", "nullify", "hash"], "scrub")
        if p["mode"] == "scrub":
            detectors: Dict[str, Dict[str, str]] = {}
            for det in ("email", "ssn", "credit_card", "phone", "ip_address", "date"):
                linkable = [d.name for d in domains.values() if d.type == {"credit_card": "credit_card"}.get(det, det)]
                options = ["tag", "remove", "skip"] + (["mask"] if linkable else [])
                action = prompts.choose("    %s found in the text ->" % det, options,
                                        "mask" if linkable else ("skip" if det in ("ip_address", "date") else "tag"))
                if action == "skip":
                    continue
                spec = {"action": action}
                if action == "mask":
                    spec["domain"] = prompts.choose("      mask with domain", linkable, linkable[0])
                elif action == "tag":
                    spec["tag"] = "[%s]" % det.upper()
                detectors[det] = spec
            p["detectors"] = detectors
            p["on_overflow"] = prompts.choose("    If scrubbed text no longer fits the column", ["truncate", "error"],
                                              "truncate")
    return p


def _ask_params(mtype: str, skip=frozenset()) -> Dict[str, object]:
    cls = get_masker_class(mtype)
    simple = {k: v for k, v in cls.default_params.items()
              if k not in skip and not isinstance(v, (dict, list)) and k not in ("normalize", "pad_to", "shift_by")}
    if not simple:
        return {}
    print("    %s - %s" % (mtype, cls.description))
    if not prompts.ask_yes_no("    Customise other parameters %s?" % simple, False):
        return {}
    params: Dict[str, object] = {}
    for name, default in simple.items():
        if isinstance(default, bool):
            val: object = prompts.ask_yes_no("      %s" % name, default)
        elif isinstance(default, int):
            val = prompts.ask_int("      %s" % name, default)
        else:
            val = prompts.ask("      %s" % name, str(default))
        if val != default:
            params[name] = val
    cls.validate_params(params)
    return params
