"""Masker base class, errors and shared helpers used by every masking algorithm."""

from __future__ import annotations

import hmac
from typing import Any, Dict, FrozenSet, List, Optional, Tuple


class MaskerError(ValueError):
    """Invalid masker configuration or a value that cannot be masked."""


class BaseMasker:
    type_name = ""
    description = ""
    default_params: Dict[str, Any] = {}
    #: params that only change how the result is rendered; columns may override them
    format_params: FrozenSet[str] = frozenset()
    #: algorithm choices a single column may override (e.g. a name column using method: hash)
    column_params: FrozenSet[str] = frozenset()
    #: column type families this masker may be applied to
    families: Tuple[str, ...] = ("string",)
    #: True if two different inputs can never produce the same output
    injective = False
    #: True if the engine should actively check for output collisions
    collision_check = False

    def __init__(self, domain: str, key: bytes, params: Optional[Dict[str, Any]] = None):
        self.domain = domain
        self._key = key
        self.params = self.validate_params(params or {})
        self._setup()

    # -- configuration --------------------------------------------------------
    @classmethod
    def validate_params(cls, params: Dict[str, Any]) -> Dict[str, Any]:
        unknown = set(params) - set(cls.default_params)
        if unknown:
            raise MaskerError(
                "Unknown parameter(s) %s for mask type '%s'. Allowed: %s"
                % (sorted(unknown), cls.type_name, sorted(cls.default_params) or "none")
            )
        merged = dict(cls.default_params)
        merged.update(params)
        cls._check_params(merged)
        return merged

    @classmethod
    def _check_params(cls, p: Dict[str, Any]) -> None:
        pass

    @classmethod
    def column_overridable(cls) -> FrozenSet[str]:
        """Params a column entry in the rules may set for that column only."""
        return cls.format_params | cls.column_params

    @classmethod
    def entity_required(cls, params: Dict[str, Any]) -> bool:
        return False

    @classmethod
    def referenced_domains(cls, params: Dict[str, Any]) -> List[str]:
        return []

    def _setup(self) -> None:
        pass

    # -- helpers --------------------------------------------------------------
    def _digest(self, *parts: str) -> bytes:
        return hmac.digest(self._key, "\x1f".join(parts).encode("utf-8"), "sha256")

    def _int(self, *parts: str) -> int:
        return int.from_bytes(self._digest(*parts), "big")

    def _pick(self, choices, *parts: str) -> str:
        return choices[self._int(*parts) % len(choices)]

    # -- API ------------------------------------------------------------------
    def canonical(self, value: str) -> str:
        """The normalised form the mask is derived from (used for collision checks)."""
        return value

    def mask(self, value: Optional[str], entity: Optional[str] = None) -> Optional[str]:
        if value is None:
            return None
        if value.strip() == "":
            return value
        return self._mask(value)

    def _mask(self, value: str) -> Optional[str]:
        raise NotImplementedError


def _non_negative_int(p: Dict[str, Any], *names: str) -> None:
    for n in names:
        if not isinstance(p[n], int) or isinstance(p[n], bool) or p[n] < 0:
            raise MaskerError("Parameter '%s' must be a non-negative integer" % n)


def _choice(p: Dict[str, Any], name: str, allowed) -> None:
    if p[name] not in allowed:
        raise MaskerError("Parameter '%s' must be one of %s (got %r)" % (name, ", ".join(map(str, allowed)), p[name]))


def _match_case(template: str, value: str) -> str:
    if template.isupper():
        return value.upper()
    if template.islower():
        return value.lower()
    return value


def _reinsert_digits(template: str, digits: str) -> str:
    it = iter(digits)
    return "".join(next(it) if ch.isdigit() else ch for ch in template)


# Partial de-identification options shared by ssn / account_number / credit_card.
#   full          - every digit/letter is de-identified (default, recommended)
#   last4         - keep the last 4 digits, de-identify the rest
#   first6_last4  - (cards) keep BIN + last 4, PCI-DSS display style
MODES = ("full", "last4", "first6_last4")


def _apply_mode(p: Dict[str, Any], allowed=("full", "last4")) -> None:
    _choice(p, "mode", allowed)
    _non_negative_int(p, *(n for n in ("preserve_first", "preserve_last") if n in p))
    if p["mode"] == "full":
        return
    want_first, want_last = (6, 4) if p["mode"] == "first6_last4" else (0, 4)
    for name, want in (("preserve_first", want_first), ("preserve_last", want_last)):
        if name not in p:
            continue
        if p[name] not in (0, want):
            raise MaskerError("mode=%s conflicts with %s=%s; set only one of them" % (p["mode"], name, p[name]))
        p[name] = want
