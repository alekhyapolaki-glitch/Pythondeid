"""Shared CLI helpers: config file defaults, loading settings/key/logging, the masking-policy questions."""

from __future__ import annotations

import json
import logging
from pathlib import Path

from ..config import (
    PROJECT_ROOT,
    ConfigError,
    load_connections,
    load_copy_map,
    load_rules,
    load_settings,
)
from ..database.connection import ConnectionFactory
from ..masking import KeyRing
from ..utils import prompts

log = logging.getLogger("deid")


# Config files (relative to the project folder, so the tool works from any current directory):
DEFAULT_SETTINGS = str(PROJECT_ROOT / "config" / "settings.yaml")        # how it runs


DEFAULT_CONNECTIONS = str(PROJECT_ROOT / "config" / "connections.yaml")  # database connections (this machine)


DEFAULT_PATHS = str(PROJECT_ROOT / "config" / "paths.yaml")              # file and folder locations


def _load(args):
    """settings.yaml + the selected connection from connections.yaml + paths.yaml."""
    return load_settings(args.settings, args.connections, args.connection, args.paths)


def _settings(args):
    s = _load(args)
    if getattr(args, "server", None):
        s.database["server"] = args.server
    if getattr(args, "database", None):
        s.database["database"] = args.database
    if not s.database.get("database"):
        raise ConfigError("No database configured. Run 'python main.py configure' to add a connection to %s "
                          "(or pass --database)" % args.connections)
    log.debug("Using connection '%s'", s.connection_name)
    return s


def _keyring(settings) -> KeyRing:
    sec = settings.security
    return KeyRing.from_env(sec.get("secret_key_env", "DEID_SECRET_KEY"), int(sec.get("min_key_length", 32)))


def _setup_logging(settings, name="deid"):
    from deid.utils.logging_setup import setup_logging
    return setup_logging(settings.logging.get("level", "INFO"), settings.logging.get("dir", "logs"), name)


def _mode(args, settings) -> str:
    """in_place (UPDATE the database) or on_the_fly (read source, mask, write target): --mode, else settings."""
    return getattr(args, "mode", None) or settings.execution.get("mode", "in_place")


def _engine(args, settings, rules):
    from deid.engine import CopyEngine, Engine
    factory = ConnectionFactory(settings.database, interactive=not args.yes)
    if _mode(args, settings) != "on_the_fly":
        return Engine(settings, rules, _keyring(settings), factory)
    copy_map = load_copy_map(settings.paths["copy_map"], rules)
    name = getattr(args, "target_connection", None) or copy_map.target_connection
    if not name:
        raise ConfigError("On-the-fly masking needs a target: set target_connection in %s or pass "
                          "--target-connection NAME (a connection in %s)" % (settings.paths["copy_map"], args.connections))
    if not (args.connections and Path(args.connections).exists()):
        raise ConfigError("Target connection '%s' needs %s; add it with: python main.py configure" % (name, args.connections))
    _, conns = load_connections(args.connections)
    if name not in conns:
        raise ConfigError("Target connection '%s' is not in %s (available: %s)" % (name, args.connections, ", ".join(conns)))
    target = ConnectionFactory(conns[name], interactive=not args.yes)
    return CopyEngine(settings, rules, _keyring(settings), factory, target, copy_map, name)


def _rules(args, settings=None):
    """The rules file with the selected profile's policy applied (--profile)."""
    profile = None
    if getattr(args, "profile", None):
        from ..config import load_profile
        settings = settings or _load(args)
        profile = load_profile(args.profile, settings.paths["profiles_dir"])
    return load_rules(args.rules, profile)


def _plan(args):
    settings = _settings(args)
    _setup_logging(settings)
    rules = _rules(args, settings)
    engine = _engine(args, settings, rules)
    info = engine.connect()
    plan = engine.plan()
    return settings, rules, engine, info, plan


def _print_result(result):
    print("\nRun %s finished: %s" % (result["run_id"], result["status"]))
    print("  tables completed: %d / %d" % (result["tables_completed"], result["tables"]))
    print("  rows written:     %d" % result["rows_updated"])
    for f in result["failures"]:
        print("  FAILURE: %s" % f)
    print("  audit files:      %s" % result["audit_dir"])


def _last_dry_run(settings, rules, info):
    """run_id of the newest DRY_RUN_OK for the same rules, key and database, if any."""
    out_dir = Path(settings.audit.get("output_dir", "audit"))
    fingerprint = _keyring(settings).fingerprint()
    for p in sorted(out_dir.glob("*/summary.json"), reverse=True):
        try:
            d = json.loads(p.read_text(encoding="utf-8"))
        except ValueError:
            continue
        if (d.get("mode") == "dry-run" and d.get("status") == "DRY_RUN_OK" and d.get("rules_hash") == rules.content_hash
                and d.get("key_fingerprint") == fingerprint and d.get("database") == info["database"]):
            return d.get("run_id")
    return None


def current_policy(rules_path: str):
    """Policy from the rules file (even one without tables yet), else the defaults."""
    from deid.config import DEFAULT_POLICY, _parse_policy, _read_yaml
    try:
        return _parse_policy(_read_yaml(Path(rules_path)).get("policy"), rules_path)
    except ConfigError:
        return dict(DEFAULT_POLICY)


def ask_policy(rules_path: str) -> dict:
    """The masking-policy questions (full vs last4, name method); saved into the rules file."""
    from deid.config import POLICY_OPTIONS, update_policy_in_file
    policy = current_policy(rules_path)
    print("\n=== Masking policy (stored at the top of %s) ===" % rules_path)
    print("These choices apply to every column of that kind. Keeping last 4 digits reduces protection.")
    for key, (_, _, allowed, question) in POLICY_OPTIONS.items():
        policy[key] = prompts.choose(question, list(allowed), policy[key])
    update_policy_in_file(rules_path, policy)
    print("Saved policy: %s" % ", ".join("%s=%s" % kv for kv in policy.items()))
    print("Masked values change when the policy changes: use the same policy on every server.")
    return policy


def _check_key_pin(settings, keyring):
    pinned = (settings.security.get("expected_key_fingerprint") or "").strip()
    if pinned and pinned != keyring.fingerprint():
        raise ConfigError("DEID_SECRET_KEY does not match security.expected_key_fingerprint (%s, got %s)"
                          % (pinned, keyring.fingerprint()))
