"""Free-text scrubbing: find PII patterns in notes/comments and tag, remove or mask each hit."""

from __future__ import annotations

import binascii
import re
from typing import Any, Dict, List, Tuple

from .base import BaseMasker, MaskerError, _choice
from .identifiers import CreditCardMasker

BUILTIN_DETECTORS: Dict[str, str] = {
    # order = priority when patterns overlap
    "email": r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
    "credit_card": r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)",
    "ssn": r"(?<!\d)\d{3}[- ]\d{2}[- ]\d{4}(?!\d)",
    "phone": r"(?<![\w])(?:\+?\d{1,3}[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}(?!\d)",
    "ip_address": r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])",
    "date": r"(?<!\d)(?:\d{4}-\d{2}-\d{2}|\d{1,2}/\d{1,2}/\d{4})(?!\d)",
}


DEFAULT_DETECTORS = {
    "email": {"action": "tag", "tag": "[EMAIL]"},
    "credit_card": {"action": "tag", "tag": "[CARD]"},
    "ssn": {"action": "tag", "tag": "[SSN]"},
    "phone": {"action": "tag", "tag": "[PHONE]"},
}


class FreeTextMasker(BaseMasker):
    """Options (all via config):

    mode: scrub (default) | redact | nullify | hash
    detectors:            which built-in PII patterns to find and what to do with each hit
        email:  {action: mask, domain: email}   # same token as the Email columns
        ssn:    {action: tag, tag: "[SSN]"}     # replace with a fixed tag
        phone:  {action: remove}                # delete the hit
    custom_patterns:      [{name: member_id, regex: "MBR\\d{8}", action: mask, domain: account_number}]
    on_overflow:          truncate (default) | error  - if the scrubbed text exceeds the column length
    """

    type_name = "free_text"
    description = ("Notes/comments: mode=scrub finds email/SSN/card/phone/IP/date/custom regex hits and tags, "
                   "removes or masks them with another domain; or mode=redact|nullify|hash")
    default_params = {
        "mode": "scrub", "replacement": "[REDACTED]", "detectors": DEFAULT_DETECTORS,
        "custom_patterns": [], "on_overflow": "truncate",
    }

    @classmethod
    def _check_params(cls, p):
        _choice(p, "mode", ("scrub", "redact", "nullify", "hash"))
        _choice(p, "on_overflow", ("truncate", "error"))
        if not isinstance(p["detectors"], dict):
            raise MaskerError("free_text.detectors must be a mapping of detector -> {action: ...}")
        for name, spec in p["detectors"].items():
            if name not in BUILTIN_DETECTORS:
                raise MaskerError("Unknown free_text detector '%s'. Built-in: %s" % (name, ", ".join(BUILTIN_DETECTORS)))
            cls._check_action(name, spec)
        if not isinstance(p["custom_patterns"], list):
            raise MaskerError("free_text.custom_patterns must be a list")
        for cp in p["custom_patterns"]:
            if not isinstance(cp, dict) or not cp.get("name") or not cp.get("regex"):
                raise MaskerError("each custom_pattern needs 'name' and 'regex'")
            try:
                re.compile(cp["regex"])
            except re.error as exc:
                raise MaskerError("custom_pattern '%s' has an invalid regex: %s" % (cp["name"], exc)) from exc
            cls._check_action(cp["name"], cp)

    @staticmethod
    def _check_action(name, spec):
        if not isinstance(spec, dict):
            raise MaskerError("detector '%s' must be a mapping like {action: tag}" % name)
        action = spec.get("action", "tag")
        if action not in ("tag", "remove", "mask"):
            raise MaskerError("detector '%s': action must be tag, remove or mask" % name)
        if action == "mask" and not spec.get("domain"):
            raise MaskerError("detector '%s': action=mask needs a 'domain' to mask hits with" % name)

    @classmethod
    def referenced_domains(cls, params):
        specs = list((params.get("detectors") or {}).values()) + list(params.get("custom_patterns") or [])
        return [s["domain"] for s in specs if isinstance(s, dict) and s.get("action") == "mask"]

    def _setup(self):
        self.resolver: Dict[str, BaseMasker] = {}
        self._rules: List[Tuple[str, Dict[str, Any]]] = []
        parts = []
        for i, (name, spec) in enumerate(self.params["detectors"].items()):
            parts.append("(?P<b%d>%s)" % (i, BUILTIN_DETECTORS[name]))
            self._rules.append((name, spec))
        offset = len(self._rules)
        for j, cp in enumerate(self.params["custom_patterns"]):
            parts.append("(?P<b%d>%s)" % (offset + j, cp["regex"]))
            self._rules.append((cp["name"], cp))
        self._regex = re.compile("|".join(parts)) if parts else None

    def set_resolver(self, maskers: Dict[str, BaseMasker]) -> None:
        missing = [d for d in self.referenced_domains(self.params) if d not in maskers]
        if missing:
            raise MaskerError("free_text domain '%s' references undefined domain(s): %s" % (self.domain, missing))
        self.resolver = maskers

    def _replace(self, m):
        idx = int(m.lastgroup[1:])
        name, spec = self._rules[idx]
        hit = m.group(0)
        if name == "credit_card" and not CreditCardMasker.luhn_valid(re.sub(r"\D", "", hit)):
            return hit  # long digit runs that are not card numbers
        action = spec.get("action", "tag")
        if action == "remove":
            return ""
        if action == "mask":
            masker = self.resolver.get(spec["domain"])
            if masker is None:
                raise MaskerError("free_text: domain '%s' is not available" % spec["domain"])
            masked = masker.mask(hit)
            return "" if masked is None else masked
        return str(spec.get("tag") or "[%s]" % name.upper())

    def mask(self, value, entity=None):
        if value is None:
            return None
        mode = self.params["mode"]
        if mode == "nullify":
            return None
        if value.strip() == "":
            return value
        if mode == "redact":
            return str(self.params["replacement"])
        if mode == "hash":
            return binascii.hexlify(self._digest("text", value)).decode()[:32]
        return self._regex.sub(self._replace, value) if self._regex else value
