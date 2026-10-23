"""Keyed token maskers: email addresses and HMAC hashes."""

from __future__ import annotations

import base64
import binascii
import re

from .base import BaseMasker, MaskerError

EMAIL_TOKEN_LENGTH = 16  # 80 bits: collision-safe for hundreds of millions of distinct emails


class EmailMasker(BaseMasker):
    type_name = "email"
    description = "Email: deterministic token local-part @ safe domain (case-insensitive, unique)"
    default_params = {"domain": "example.com", "preserve_domain": False, "prefix": "user",
                      "token_length": EMAIL_TOKEN_LENGTH}
    collision_check = True
    injective = True

    @classmethod
    def _check_params(cls, p):
        if not isinstance(p["token_length"], int) or not 6 <= p["token_length"] <= 52:
            raise MaskerError("email.token_length must be an integer between 6 and 52")
        if not p["preserve_domain"] and not re.match(r"^[A-Za-z0-9.-]+$", str(p["domain"])):
            raise MaskerError("email.domain must be a plain domain name, e.g. example.com")

    def canonical(self, value):
        return value.strip().lower()

    def _mask(self, value):
        norm = self.canonical(value)
        local, _, domain = norm.rpartition("@")
        if not local:
            local, domain = norm, ""
        token = base64.b32encode(self._digest("email", norm)).decode("ascii").lower().rstrip("=")
        token = token[: self.params["token_length"]]
        out_domain = domain if (self.params["preserve_domain"] and domain) else self.params["domain"]
        return "%s%s@%s" % (self.params["prefix"], token, out_domain)


class HashMasker(BaseMasker):
    type_name = "hash"
    description = "Keyed HMAC-SHA256 hex token (irreversible, deterministic)"
    default_params = {"length": 32, "prefix": "", "uppercase": False, "case_sensitive": True}
    collision_check = True
    injective = True

    @classmethod
    def _check_params(cls, p):
        if not isinstance(p["length"], int) or not 8 <= p["length"] <= 64:
            raise MaskerError("hash.length must be an integer between 8 and 64")

    def canonical(self, value):
        return value if self.params["case_sensitive"] else value.strip().lower()

    def _mask(self, value):
        token = binascii.hexlify(self._digest("hash", self.canonical(value))).decode()[: self.params["length"]]
        return self.params["prefix"] + (token.upper() if self.params["uppercase"] else token)
