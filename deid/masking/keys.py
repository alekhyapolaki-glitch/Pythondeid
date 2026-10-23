"""Secret key handling: per-domain key derivation and the key fingerprint."""

from __future__ import annotations

import base64
import hashlib
import hmac
import os

from .base import MaskerError

#: Bump only if an algorithm changes output. Rules may pin it (algorithm_version: 1).
ALGORITHM_VERSION = 1


class KeyRing:
    """Holds the master secret and derives one independent key per domain."""

    def __init__(self, master_key: bytes):
        if len(master_key) < 16:
            raise MaskerError("Secret key is too short (need at least 16 bytes of entropy)")
        self._master = master_key

    @classmethod
    def from_string(cls, secret: str, min_length: int = 32) -> KeyRing:
        secret = secret.strip()
        if len(secret) < min_length:
            raise MaskerError(
                "Secret key must be at least %d characters. Generate one with: python main.py genkey" % min_length
            )
        return cls(secret.encode("utf-8"))

    @classmethod
    def from_env(cls, env_var: str, min_length: int = 32) -> KeyRing:
        secret = os.environ.get(env_var)
        if not secret:
            raise MaskerError(
                "Environment variable %s is not set. Generate a key with 'python main.py genkey' and set it "
                "before running (the same key must be used on every server to keep masking consistent)." % env_var
            )
        return cls.from_string(secret, min_length)

    @staticmethod
    def generate() -> str:
        return base64.urlsafe_b64encode(os.urandom(48)).decode("ascii")

    def domain_key(self, domain: str) -> bytes:
        return hmac.new(self._master, b"pythondeid-domain-v1|" + domain.encode("utf-8"), hashlib.sha256).digest()

    def fingerprint(self) -> str:
        """Non-reversible identifier of the key, safe to store in audit records and config."""
        return hmac.new(self._master, b"pythondeid-fingerprint", hashlib.sha256).hexdigest()[:16]
