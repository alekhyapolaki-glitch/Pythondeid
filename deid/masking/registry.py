"""Registry of mask types and the factory functions that build maskers for domains and columns."""

from __future__ import annotations

from typing import Any, Dict, Optional, Type

from .base import BaseMasker, MaskerError
from .free_text import FreeTextMasker
from .generalize import DateShiftMasker, NullifyMasker, RedactMasker, ZipMasker
from .identifiers import AccountNumberMasker, CreditCardMasker, FpeMasker, PhoneMasker, SsnMasker
from .keys import KeyRing
from .names import (
    AccountNameMasker,
    CityMasker,
    FirstNameMasker,
    FullNameMasker,
    LastNameMasker,
    MethodChoiceMasker,
    StreetAddressMasker,
)
from .tokens import EmailMasker, HashMasker

MASKERS: Dict[str, Type[BaseMasker]] = {
    cls.type_name: cls
    for cls in (
        EmailMasker, SsnMasker, AccountNumberMasker, CreditCardMasker, PhoneMasker, FpeMasker, HashMasker,
        FirstNameMasker, LastNameMasker, FullNameMasker, StreetAddressMasker, CityMasker, ZipMasker,
        DateShiftMasker, RedactMasker, NullifyMasker, FreeTextMasker, AccountNameMasker,
    )
}


def get_masker_class(type_name: str) -> Type[BaseMasker]:
    try:
        return MASKERS[type_name]
    except KeyError:
        raise MaskerError("Unknown mask type '%s'. Available: %s" % (type_name, ", ".join(sorted(MASKERS)))) from None


def create_masker(type_name: str, domain: str, keyring: KeyRing, params: Optional[Dict[str, Any]] = None) -> BaseMasker:
    return get_masker_class(type_name)(domain, keyring.domain_key(domain), params)


def build_maskers(domains, keyring: KeyRing) -> Dict[str, BaseMasker]:
    """One masker per domain (DomainRule-like objects with name/type/params), with free-text links resolved."""
    maskers = {d.name: create_masker(d.type, d.name, keyring, d.params) for d in domains}
    for m in maskers.values():
        if isinstance(m, FreeTextMasker):
            m.set_resolver(maskers)
    return maskers


def column_masker(base: BaseMasker, keyring: KeyRing, overrides: Dict[str, Any]) -> BaseMasker:
    """A masker for one column with its overrides (format, or a per-column method); same domain key."""
    if not overrides:
        return base
    bad = set(overrides) - set(base.column_overridable())
    if bad:
        raise MaskerError("Column overrides %s are not allowed for '%s' (allowed: %s)"
                          % (sorted(bad), base.type_name, sorted(base.column_overridable()) or "none"))
    m = type(base)(base.domain, keyring.domain_key(base.domain), dict(base.params, **overrides))
    if isinstance(base, FreeTextMasker):
        m.set_resolver(base.resolver)
    return m


def is_injective(type_name: str, params: Optional[Dict[str, Any]] = None) -> bool:
    """True if different inputs can never share a masked value (params: domain params merged with column overrides)."""
    cls = get_masker_class(type_name)
    if cls is ZipMasker:
        return (params or {}).get("mode", "truncate") == "fpe"
    if issubclass(cls, MethodChoiceMasker):
        return (params or {}).get("method", "realistic") == "hash"
    return cls.injective
