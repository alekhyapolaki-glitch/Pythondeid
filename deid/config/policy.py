"""The masking policy (full vs last4, name/address methods, ...) at the top of deid_rules.yaml."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, Tuple

from ..masking import MODES, NAME_METHODS, PHONE_MODES, MaskerError, get_masker_class
from .base import ConfigError

if TYPE_CHECKING:  # rules.py imports this module
    from .rules import DomainRule


POLICY_OPTIONS: Dict[str, Tuple[Tuple[str, ...], str, Tuple[str, ...], str]] = {
    # policy key:      (mask types,                     param,    allowed values, question)
    "ssn":            (("ssn",), "mode", ("full", "last4"), "SSN: de-identify fully, or keep the last 4 digits?"),
    "account_number": (("account_number",), "mode", ("full", "last4"),
                       "Account numbers: de-identify fully, or keep the last 4 characters?"),
    "credit_card":    (("credit_card",), "mode", tuple(MODES),
                       "Card numbers: full, last4, or first6_last4 (keep BIN + last 4)?"),
    "names":          (("first_name", "last_name", "full_name", "account_name"), "method", tuple(NAME_METHODS),
                       "Names: realistic (fake names), hash (unique code) or redact (constant)?"),
    "phone":          (("phone",), "mode", tuple(PHONE_MODES),
                       "Phone numbers: full, last4, or area_code (keep area code, mask the rest)?"),
    "address":        (("street_address",), "method", tuple(NAME_METHODS),
                       "Street addresses: realistic (fake address), hash (unique code) or redact (constant)?"),
    "city":           (("city",), "method", tuple(NAME_METHODS),
                       "Cities: realistic (fake city), hash (unique code) or redact (constant)?"),
    "zip":            (("zip",), "mode", ("truncate", "hipaa", "fpe"),
                       "ZIP codes: truncate (keep first 3 digits), hipaa (same, plus low-population areas -> 000) "
                       "or fpe (all digits de-identified)?"),
    "dates":          (("date_shift",), "generalize", ("shift", "month", "year"),
                       "Dates: shift (realistic, per-person offset), month (yyyy-mm-01) or year (yyyy-01-01, "
                       "HIPAA Safe Harbor)?"),
    "free_text":      (("free_text",), "mode", ("scrub", "redact", "nullify", "hash"),
                       "Free text: scrub (replace PII found in the text), redact, nullify or hash?"),
}
#: policy values that are spelled differently from the masker parameter they set
POLICY_VALUE_MAP: Dict[str, Dict[str, str]] = {"dates": {"shift": "none"}}


DEFAULT_POLICY = {"ssn": "full", "account_number": "full", "credit_card": "full", "names": "realistic",
                  "phone": "full", "address": "realistic", "city": "realistic", "zip": "truncate",
                  "dates": "shift", "free_text": "scrub"}


def _parse_policy(raw: Any, source: str) -> Dict[str, str]:
    if raw is None:
        return dict(DEFAULT_POLICY)
    if not isinstance(raw, dict):
        raise ConfigError("%s: 'policy' must be a mapping like {ssn: full, account_number: last4}" % source)
    unknown = set(raw) - set(POLICY_OPTIONS)
    if unknown:
        raise ConfigError("%s: unknown policy key(s) %s. Allowed: %s" % (source, sorted(unknown), sorted(POLICY_OPTIONS)))
    policy = dict(DEFAULT_POLICY)
    for k, v in raw.items():
        allowed = POLICY_OPTIONS[k][2]
        if str(v) not in allowed:
            raise ConfigError("%s: policy.%s must be one of %s (got %r)" % (source, k, ", ".join(allowed), v))
        policy[k] = str(v)
    return policy


def _apply_policy(domains: Dict[str, DomainRule], policy: Dict[str, str], source: str) -> None:
    for key, (types, param, _, _) in POLICY_OPTIONS.items():
        for d in domains.values():
            if d.type in types and param not in d.params:
                d.params[param] = POLICY_VALUE_MAP.get(key, {}).get(policy[key], policy[key])
                d.policy_keys.append(param)
                try:
                    get_masker_class(d.type).validate_params(d.params)
                except MaskerError as exc:
                    raise ConfigError("%s: policy.%s=%s cannot apply to domain '%s': %s"
                                      % (source, key, policy[key], d.name, exc)) from exc


_POLICY_COMMENTS = {
    "ssn": "full | last4",
    "account_number": "full | last4",
    "credit_card": "full | last4 | first6_last4",
    "names": "realistic | hash | redact   (first/last/full/account name columns; a column may override)",
    "phone": "full | last4 | area_code",
    "address": "realistic | hash | redact   (street_address columns)",
    "city": "realistic | hash | redact",
    "zip": "truncate | hipaa (3 digits, low-population areas -> 000) | fpe",
    "dates": "shift (per-person offset) | month | year (HIPAA Safe Harbor)",
    "free_text": "scrub | redact | nullify | hash",
}


def update_policy_in_file(path: str, policy: Dict[str, str]) -> None:
    """Write the policy block into deid_rules.yaml in place, keeping every other line and comment."""
    p = Path(path)
    lines = p.read_text(encoding="utf-8").splitlines() if p.exists() else []
    block = ["policy:                   # masking choices; apply to every domain of these types that does not "
             "set them itself"]
    block += ["  %-16s %-14s # %s" % (k + ":", policy[k], _POLICY_COMMENTS[k]) for k in POLICY_OPTIONS]
    start = next((i for i, ln in enumerate(lines) if ln.split("#")[0].rstrip() == "policy:"), None)
    if start is not None:
        end = start + 1
        while end < len(lines) and (lines[end].startswith((" ", "\t")) or not lines[end].strip()):
            end += 1
        while end > start + 1 and not lines[end - 1].strip():
            end -= 1  # keep blank lines that follow the block
        lines[start:end] = block
    else:
        at = next((i + 1 for i, ln in enumerate(lines) if ln.startswith("algorithm_version")), None)
        if at is None:
            at = next((i for i, ln in enumerate(lines) if ln.strip() and not ln.lstrip().startswith("#")), len(lines))
        lines[at:at] = ["", *block, ""]
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
