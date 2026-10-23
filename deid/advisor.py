"""Recommendations: input/output data types per mask type, batch sizing for big tables,
database readiness checks (SQL Server 2022) and column profiling."""

from __future__ import annotations

import logging
import os
import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .database.schema import ColumnInfo, TableInfo
from .database.sql import quote_ident
from .masking import data, get_masker_class

log = logging.getLogger(__name__)
MB = 1024 * 1024

# =============================================================================
# Input / output data type guide
# =============================================================================
TYPE_GUIDE: Dict[str, Dict[str, str]] = {
    "ssn": {
        "input": "char(9), char(11), varchar(9..11), int/bigint (zero-padded to 9 digits)",
        "output": "same as input. output_format=dashed needs char(11)/varchar(11); digits needs char(9) or int",
        "notes": "mode=last4 keeps the last 4 digits (reduced protection; not HIPAA Safe Harbor)",
    },
    "account_number": {
        "input": "varchar/char/nvarchar, int/bigint/decimal(p,0)",
        "output": "same type and length as input; with normalize=digits the column must hold pad_to digits",
        "notes": "use normalize: digits + pad_to when the same number is stored as text in one table and as a "
                 "number (or without leading zeros) in another",
    },
    "fpe": {"input": "varchar/char/nvarchar, int/bigint/decimal", "output": "same as input", "notes": ""},
    "phone": {"input": "varchar(10..20)", "output": "same as input (punctuation kept)", "notes": ""},
    "credit_card": {
        "input": "varchar(12..19) or char(16), bigint/decimal(19,0)",
        "output": "same as input; output_format=grouped needs varchar(23)",
        "notes": "mode=full | last4 | first6_last4",
    },
    "email": {
        "input": "varchar/nvarchar",
        "output": "varchar(len(prefix) + token_length + 1 + len(domain)) = varchar(32) with defaults",
        "notes": "lower token_length only for small datasets (collision checks run regardless)",
    },
    "hash": {"input": "any text", "output": "varchar(len(prefix) + length)", "notes": ""},
    "first_name": {"input": "varchar/nvarchar", "output": "nvarchar(%d) or longer" % max(map(len, data.FIRST_NAMES)), "notes": ""},
    "last_name": {"input": "varchar/nvarchar", "output": "nvarchar(%d) or longer" % max(map(len, data.LAST_NAMES)), "notes": ""},
    "full_name": {"input": "varchar/nvarchar", "output": "nvarchar(50) or longer recommended", "notes": ""},
    "account_name": {
        "input": "varchar/nvarchar holding person OR business names",
        "output": "same as input; nvarchar(60)+ recommended (fake company words can be longer than the original)",
        "notes": "INC/LLC/LTD and industry words are kept; add your own generic words via extra_business_words",
    },
    "street_address": {"input": "varchar/nvarchar", "output": "nvarchar(30) or longer", "notes": ""},
    "city": {"input": "varchar/nvarchar", "output": "nvarchar(%d) or longer" % max(map(len, data.CITIES)), "notes": ""},
    "zip": {"input": "char(5), varchar(10), int", "output": "same as input", "notes": ""},
    "date_shift": {
        "input": "date, datetime, datetime2, smalldatetime, datetimeoffset, or ISO/US date strings",
        "output": "same as input (time-of-day and offset kept)",
        "notes": "shift_by: entity + entity_column keeps intervals between one person's dates",
    },
    "redact": {"input": "any text", "output": "length of 'value' (or same length with preserve_length)", "notes": ""},
    "nullify": {"input": "any nullable column", "output": "NULL", "notes": "column must allow NULL"},
    "free_text": {
        "input": "varchar/nvarchar/text/ntext (notes, comments)",
        "output": "same column; on_overflow=truncate cuts text that grows past the column length",
        "notes": "regex detection cannot find names or PII written in prose; use mode=redact for high risk text",
    },
}


def required_output_chars(mtype: str, params: Dict[str, Any], input_chars: Optional[int]) -> Optional[int]:
    """Longest masked value (in characters) the column must be able to hold; None if unknown/variable."""
    p = get_masker_class(mtype).validate_params(params or {})
    if mtype == "email":
        return None if p["preserve_domain"] else len(p["prefix"]) + p["token_length"] + 1 + len(p["domain"])
    if mtype == "hash":
        return len(p["prefix"]) + p["length"]
    if mtype == "ssn":
        return {"dashed": 11, "digits": 9}.get(p["output_format"], input_chars)
    if mtype == "credit_card" and p["output_format"] == "grouped":
        return 23
    if mtype in ("fpe", "account_number", "phone") and p.get("normalize") == "digits":
        return max(p["pad_to"], input_chars or 0)
    if mtype == "first_name":
        return max(map(len, data.FIRST_NAMES))
    if mtype == "last_name":
        return max(map(len, data.LAST_NAMES))
    if mtype == "city":
        return max(map(len, data.CITIES))
    if mtype == "street_address":
        return 4 + 1 + max(map(len, data.STREET_NAMES)) + 1 + max(map(len, data.STREET_SUFFIXES))
    if mtype == "redact":
        return input_chars if p["preserve_length"] else len(str(p["value"]))
    if mtype in ("nullify", "full_name", "free_text", "account_name"):
        return None
    return input_chars


# =============================================================================
# Batch sizing
# =============================================================================
def recommend_batch_size(table: TableInfo, batching: Dict[str, Any]) -> int:
    """Rows per committed chunk so each chunk rewrites roughly target_batch_mb of data."""
    target = int(batching.get("target_batch_mb", 256)) * MB
    rows = target // max(table.avg_row_bytes, 1)
    rows = max(int(batching.get("min_batch_size", 10000)), min(int(batching.get("max_batch_size", 500000)), rows))
    # round to a readable number
    rows = int(round(rows, -3)) if rows >= 10000 else rows
    return max(1, min(rows, max(table.row_count, 1)))


def estimate_log_mb(table: TableInfo, rows: Optional[int] = None) -> int:
    """Very rough transaction-log need: before + after images of the data rewritten, plus index updates."""
    n = table.row_count if rows is None else rows
    return int(n * table.avg_row_bytes * 2.5 / MB) + 1


def resolve_workers(setting) -> int:
    if setting == "auto":
        return max(1, min(8, (os.cpu_count() or 2) - 1))
    return max(1, int(setting))


# =============================================================================
# Database readiness (SQL Server 2022 large-table guidance)
# =============================================================================
@dataclass
class DbHealth:
    facts: Dict[str, Any] = field(default_factory=dict)
    advice: List[str] = field(default_factory=list)


def database_health(conn, largest_single_log_mb: int = 0, total_rows: int = 0) -> DbHealth:
    h = DbHealth()
    cur = conn.cursor()
    try:
        cur.execute(
            "SELECT recovery_model_desc, compatibility_level, is_accelerated_database_recovery_on, "
            "CAST(SERVERPROPERTY('ProductMajorVersion') AS INT) FROM sys.databases WHERE name = DB_NAME()")
        rm, compat, adr, major = cur.fetchone()
        h.facts.update(recovery_model=rm, compatibility_level=compat, accelerated_database_recovery=bool(adr),
                       sql_major_version=major)
    except Exception as exc:
        log.debug("database facts unavailable: %s", exc)
    try:
        cur.execute("SELECT total_log_size_in_bytes, used_log_space_in_bytes FROM sys.dm_db_log_space_usage")
        total, used = cur.fetchone()
        h.facts.update(log_size_mb=int(total / MB), log_free_mb=int((total - used) / MB))
    except Exception as exc:
        log.debug("log usage unavailable: %s", exc)
    try:
        cur.execute("SELECT SUM(unallocated_extent_page_count) * 8 / 1024 FROM tempdb.sys.dm_db_file_space_usage")
        h.facts["tempdb_free_mb"] = int(cur.fetchone()[0] or 0)
    except Exception as exc:
        log.debug("tempdb usage unavailable: %s", exc)

    if h.facts.get("recovery_model") == "FULL":
        h.advice.append("Recovery model is FULL: on the masking copy switch to SIMPLE "
                        "(ALTER DATABASE CURRENT SET RECOVERY SIMPLE) so committed chunks free log space, or take "
                        "frequent log backups during the run.")
    if h.facts.get("sql_major_version", 0) >= 15 and not h.facts.get("accelerated_database_recovery"):
        h.advice.append("Accelerated Database Recovery is OFF. On SQL Server 2019/2022 enable it on the masking copy "
                        "(ALTER DATABASE CURRENT SET ACCELERATED_DATABASE_RECOVERY = ON) so large single-statement "
                        "updates can be rolled back instantly and log truncation is not blocked.")
    if largest_single_log_mb and "log_free_mb" in h.facts and largest_single_log_mb > h.facts["log_free_mb"]:
        h.advice.append("The largest single-transaction table needs roughly %d MB of log but only %d MB is free; "
                        "pre-grow the log file (ALTER DATABASE ... MODIFY FILE) before running."
                        % (largest_single_log_mb, h.facts["log_free_mb"]))
    if total_rows > 10000000:
        h.advice.append("tempdb holds the value maps and sorts for DISTINCT/GROUP BY scans: keep several GB free "
                        "(currently %s MB) and use multiple equally sized tempdb files." % h.facts.get("tempdb_free_mb", "?"))
        h.advice.append("Run on a quiet copy: the tool takes table-level locks via large batches; set "
                        "execution.workers to the number of spare CPU cores for faster masking.")
    return h


# =============================================================================
# Column profiling and per-column recommendations
# =============================================================================
def _pattern(value: str) -> str:
    out = re.sub(r"[0-9]", "9", value)
    out = re.sub(r"[A-Za-z]", "A", out)
    return re.sub(r"(9+|A+)", lambda m: "%s{%d}" % (m.group(0)[0], len(m.group(0))) if len(m.group(0)) > 3 else m.group(0), out)


def profile_column(conn, table: TableInfo, col: ColumnInfo, sample: int = 5000) -> Dict[str, Any]:
    from .database.sql import text_expr
    cur = conn.cursor()
    cur.execute("SELECT TOP (?) %s FROM %s.%s AS t WHERE t.%s IS NOT NULL" % (  # nosec B608
        text_expr("t", col), quote_ident(table.schema), quote_ident(table.name), quote_ident(col.name)), [sample])
    values = [r[0] for r in cur.fetchall()]
    if not values:
        return {"sampled": 0}
    lengths = [len(v) for v in values]
    digit_counts = [sum(ch.isdigit() for ch in v) for v in values]
    patterns = Counter(_pattern(v.strip()) for v in values).most_common(3)
    return {
        "sampled": len(values),
        "min_len": min(lengths),
        "max_len": max(lengths),
        "max_digits": max(digit_counts),
        "all_digits_pct": round(100.0 * sum(v.strip().isdigit() for v in values) / len(values), 1),
        "leading_zero_pct": round(100.0 * sum(v.strip().startswith("0") for v in values) / len(values), 1),
        "top_patterns": ", ".join("%s (%d%%)" % (p, round(100.0 * n / len(values))) for p, n in patterns),
    }


def column_recommendations(plan, conn, sample: int = 5000) -> List[Dict[str, Any]]:
    """One row per planned column: type facts, profile, required output length, and advice."""
    rows: List[Dict[str, Any]] = []
    by_domain: Dict[str, List[Dict[str, Any]]] = {}
    for tp in plan.tables:
        for cp in tp.columns:
            ci = cp.info
            prof = profile_column(conn, tp.info, ci, sample) if not cp.is_nullify else {"sampled": 0}
            need = required_output_chars(cp.domain.type, dict(cp.domain.params, **cp.overrides), ci.max_chars)
            target = cp.output_info or ci
            advice: List[str] = []
            if need and target.max_chars and target.max_chars > 0 and need > target.max_chars:
                advice.append("masked values need %d chars but %s holds %d" % (need, target.type_display(), target.max_chars))
            if cp.domain.type == "date_shift" and cp.domain.params.get("shift_by", "value") == "value":
                advice.append("consider shift_by: entity with entity_column (person id) to keep date intervals")
            if cp.domain.type in ("redact", "free_text") and ci.family == "string" and ci.max_chars == -1:
                advice.append("long free text: review samples after dry-run; prose may contain names")
            row = {
                "table": tp.fqn, "column": ci.name, "actual_type": ci.type_display(),
                "expected_input_type": cp.expected_input_type or "", "output_type": target.type_display(),
                "domain": cp.domain.name, "mask_type": cp.domain.type, "required_output_chars": need or "",
                "strategy": tp.strategy, "batch_size": tp.batch_size if tp.strategy == "chunked" else "",
                "recommended_types": TYPE_GUIDE.get(cp.domain.type, {}).get("output", ""),
            }
            row.update({k: prof.get(k, "") for k in ("sampled", "min_len", "max_len", "max_digits",
                                                      "all_digits_pct", "leading_zero_pct", "top_patterns")})
            row["advice"] = advice
            rows.append(row)
            by_domain.setdefault(cp.domain.name, []).append(dict(row, family=ci.family, params=cp.domain.params))

    # Cross-column advice per domain: mixed representations break consistency unless normalised.
    for dname, cols in by_domain.items():
        families = {c["family"] for c in cols}
        mtype = cols[0]["mask_type"]
        mixed_zero = any(c.get("leading_zero_pct") not in ("", 0, 0.0) for c in cols) and len(cols) > 1
        if (mtype in ("fpe", "account_number", "phone") and cols[0]["params"].get("normalize", "none") != "digits"
                and (len(families) > 1 or mixed_zero)):
            pad = max([c["max_digits"] or 0 for c in cols] + [1])
            msg = ("domain '%s' is stored as %s across tables%s: set params {normalize: digits, pad_to: %d} so the "
                   "same number masks identically everywhere" % (
                       dname, "/".join(sorted(families)), " with leading zeros" if mixed_zero else "", pad))
            for c in rows:
                if c["domain"] == dname:
                    c["advice"].append(msg)
        if mtype == "ssn":
            pats = {c["top_patterns"].split(" (")[0] for c in cols if c["top_patterns"]}
            if len(pats) > 1:
                for c in rows:
                    if c["domain"] == dname:
                        c["advice"].append("SSN formats differ between columns (%s); masks still match on digits. "
                                           "Use output_format per column to standardise" % ", ".join(sorted(pats)))
    for r in rows:
        r["advice"] = "; ".join(r["advice"])
    return rows
