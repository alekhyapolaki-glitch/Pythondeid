"""Deterministic masking algorithms.

Consistency guarantee: a masked value depends only on (secret key, algorithm version, domain name and
parameters, canonical input), so the same input masks identically in every table, file, database and
server that uses the same key and rules.

Modules
    keys         secret key, per-domain key derivation, fingerprint
    base         BaseMasker, MaskerError, shared helpers
    fpe          Feistel format-preserving cipher (bijective)
    identifiers  fpe, account_number, phone, ssn, credit_card
    tokens       email, hash
    names        first/last/full/account names, street address, city (method: realistic | hash | redact)
    generalize   zip, date_shift, redact, nullify
    free_text    PII scrubbing inside text
    registry     MASKERS, create_masker, build_maskers, column_masker, is_injective
    data         substitution word lists
"""

from .base import MODES, BaseMasker, MaskerError
from .generalize import normalize_entity
from .identifiers import PHONE_MODES
from .keys import ALGORITHM_VERSION, KeyRing
from .names import NAME_METHODS
from .registry import MASKERS, build_maskers, column_masker, create_masker, get_masker_class, is_injective

__all__ = [
    "ALGORITHM_VERSION", "MASKERS", "MODES", "NAME_METHODS", "PHONE_MODES", "BaseMasker", "KeyRing", "MaskerError",
    "build_maskers", "column_masker", "create_masker", "get_masker_class", "is_injective", "normalize_entity",
]
