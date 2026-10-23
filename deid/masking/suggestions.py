"""Column-name heuristics that suggest a mask type (used by database discovery, the wizard and file discovery)."""

from __future__ import annotations

import re
from typing import List, Optional, Tuple

from .registry import get_masker_class


# Ordered: first match wins. Patterns run against the lower-cased column name.
SUGGESTIONS: List[Tuple[str, str]] = [
    (r"e_?mail", "email"),
    (r"(^|_)ssn($|_)|social_?sec|ss_?num|(^|_)(tin|itin)($|_)|tax_?id|national_?id", "ssn"),
    (r"credit_?card|card_?(no|num)|(^|_)cc_?(no|num)|(^|_)pan($|_)", "credit_card"),
    (r"acc(oun)?t_?(no|num|number|id)?$|iban|routing|member_?(no|num|id)|policy_?(no|num)|mrn|medical_?record", "account_number"),
    (r"phone|mobile|cell|(^|_)fax|(^|_)tel($|_)", "phone"),
    (r"first_?name|(^|_)fname|given_?name|forename", "first_name"),
    (r"last_?name|(^|_)lname|surname|family_?name", "last_name"),
    (r"acc(oun)?t_?name|customer_?name|cust_?name|client_?name|party_?name|borrower_?name|owner_?name|"
     r"name_?on_?acc", "account_name"),
    (r"full_?name|^name$|patient_?name|contact_?name", "full_name"),
    (r"address|(^|_)addr|street", "street_address"),
    (r"(^|_)city($|_)|town", "city"),
    (r"zip|postal|post_?code", "zip"),
    (r"(^|_)dob($|_)|birth", "date_shift"),
    (r"passport|driver_?lic|license_?(no|num)", "fpe"),
]


def _snake(name: str) -> str:
    s = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name)
    return re.sub(r"[^a-z0-9]+", "_", s.lower()).strip("_")


def suggest_type(col) -> Optional[str]:
    """col: anything with .name and .family (a database ColumnInfo, or a file header wrapped the same way)."""
    n = _snake(col.name)
    for pattern, mtype in SUGGESTIONS:
        if re.search(pattern, n) and col.family in get_masker_class(mtype).families:
            return mtype
    return None
