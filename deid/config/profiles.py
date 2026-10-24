"""Masking profiles (config/profiles/<name>.yaml): a named policy for an audience, e.g. 'internal' for
dev/QA/analysts and 'external' for vendors.  The profile's policy overrides the policy in
deid_rules.yaml; domains and tables are shared, so both profiles mask the same columns."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List

from .base import ConfigError, _read_yaml
from .policy import POLICY_OPTIONS

_PROFILE_KEYS = {"description", "policy"}


@dataclass
class Profile:
    name: str
    description: str = ""
    policy: Dict[str, str] = field(default_factory=dict)
    source_path: Path = Path()


def list_profiles(profiles_dir: str) -> List[str]:
    d = Path(profiles_dir)
    return sorted(p.stem for p in d.glob("*.yaml")) if d.is_dir() else []


def load_profile(name: str, profiles_dir: str) -> Profile:
    if not name or not name.replace("_", "").replace("-", "").isalnum():
        raise ConfigError("Invalid profile name %r (letters, digits, - and _ only)" % name)
    path = Path(profiles_dir) / ("%s.yaml" % name)
    if not path.exists():
        raise ConfigError("Profile '%s' not found in %s (available: %s)"
                          % (name, profiles_dir, ", ".join(list_profiles(profiles_dir)) or "none"))
    raw = _read_yaml(path)
    unknown = set(raw) - _PROFILE_KEYS
    if unknown:
        raise ConfigError("%s: unknown key(s) %s (allowed: %s)" % (path, sorted(unknown), sorted(_PROFILE_KEYS)))
    policy = raw.get("policy") or {}
    if not isinstance(policy, dict):
        raise ConfigError("%s: 'policy' must be a mapping" % path)
    for key, value in policy.items():
        if key not in POLICY_OPTIONS:
            raise ConfigError("%s: unknown policy key '%s' (allowed: %s)" % (path, key, ", ".join(POLICY_OPTIONS)))
        if str(value) not in POLICY_OPTIONS[key][2]:
            raise ConfigError("%s: policy.%s must be one of %s (got %r)"
                              % (path, key, ", ".join(POLICY_OPTIONS[key][2]), value))
    return Profile(name, str(raw.get("description") or ""), {k: str(v) for k, v in policy.items()}, path)
