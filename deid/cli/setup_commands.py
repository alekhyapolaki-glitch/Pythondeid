"""Setup commands: genkey, key-fingerprint, configure, connections, policy, test-connection."""

from __future__ import annotations

from pathlib import Path

from ..config import (
    ConfigError,
    load_rules,
    load_settings,
    save_settings,
)
from ..database.connection import ConnectionFactory, server_info
from ..masking import ALGORITHM_VERSION, KeyRing
from ..utils import prompts
from .common import _keyring, _load, _settings, ask_policy


def cmd_genkey(args):
    key = KeyRing.generate()
    print("New secret key (store it in a vault; every run must use the SAME key for consistent masking):\n")
    print("  " + key + "\n")
    print("Windows (current session):   set DEID_SECRET_KEY=" + key)
    print("Windows (persist for user):  setx DEID_SECRET_KEY \"" + key + "\"")
    print("PowerShell:                  $env:DEID_SECRET_KEY=\"" + key + "\"")
    print("Linux/macOS:                 export DEID_SECRET_KEY='" + key + "'")
    return 0


def cmd_key_fingerprint(args):
    settings = _load(args)
    fp = _keyring(settings).fingerprint()
    print("Key fingerprint: %s  (algorithm version %d)" % (fp, ALGORITHM_VERSION))
    print("Pin it on every server in settings.yaml:  security.expected_key_fingerprint: %s" % fp)
    return 0


def cmd_test_connection(args):
    settings = _settings(args)
    conn = ConnectionFactory(settings.database, interactive=not args.yes).connect(autocommit=True)
    info = server_info(conn)
    conn.close()
    for k, v in info.items():
        print("  %-12s %s" % (k, v))
    print("Connection OK")
    return 0


def cmd_configure(args):
    """Questions -> connections.yaml (database), settings.yaml (behaviour), paths.yaml, policy in the rules file."""
    from deid.config import DEFAULT_CONNECTION, load_connections, save_connection
    from deid.config import DEFAULT_PATHS as PATH_DEFAULTS
    # ---- database connection -> connections.yaml
    existing_default, conns = (load_connections(args.connections) if Path(args.connections).exists() else ("", {}))
    print("=== Database connection (saved in %s) ===" % args.connections)
    if conns:
        print("Existing connections: %s (default: %s)" % (", ".join(conns), existing_default))
    name = prompts.ask("Connection name (e.g. dev, uat, masking_copy)", args.connection or existing_default or "dev")
    db = dict(conns.get(name) or DEFAULT_CONNECTION)
    db["server"] = prompts.ask("SQL Server host[,port] or host\\instance", db.get("server") or "localhost")
    db["database"] = prompts.ask("Database name (a NON-production copy)", db.get("database") or None)
    db["driver"] = prompts.ask("ODBC driver", db.get("driver"))
    db["auth"] = prompts.choose("Authentication", ["windows", "sql", "azure_ad_interactive", "azure_ad_password"],
                                db.get("auth", "windows"))
    if db["auth"] != "windows":
        db["username"] = prompts.ask("Username", db.get("username") or None)
    if db["auth"] in ("sql", "azure_ad_password"):
        db["password_env"] = prompts.ask("Environment variable holding the password", db.get("password_env"))
    db["encrypt"] = prompts.ask_yes_no("Encrypt the connection?", bool(db.get("encrypt", True)))
    db["trust_server_certificate"] = prompts.ask_yes_no(
        "Trust the server certificate (internal/self-signed certificates)?", bool(db.get("trust_server_certificate")))
    make_default = (not conns or name == existing_default
                    or prompts.ask_yes_no("Make '%s' the default connection?" % name, False))
    save_connection(args.connections, name, db, make_default)
    print("Saved connection '%s' to %s" % (name, args.connections))

    # ---- behaviour -> settings.yaml
    settings = load_settings(args.settings, None, None, args.paths)
    before = settings.to_dict()
    ex = settings.execution
    print("\n=== Run settings (saved in %s) ===" % args.settings)
    raw_bs = prompts.ask("Rows per update batch ('auto' sizes each table from its row size)", str(ex["batch_size"]))
    ex["batch_size"] = "auto" if raw_bs.strip().lower() == "auto" else max(1, int(raw_bs))
    ex["disable_triggers"] = prompts.ask_yes_no("Disable table triggers while masking?", bool(ex["disable_triggers"]))
    ex["auto_include_fk_columns"] = prompts.ask_yes_no(
        "Automatically mask FK-related columns with the same domain?", bool(ex["auto_include_fk_columns"]))
    settings.audit["write_to_db"] = prompts.ask_yes_no(
        "Write audit tables into the database (schema %s)?" % settings.audit["schema"],
        bool(settings.audit["write_to_db"]))
    if settings.to_dict() != before or not Path(args.settings).exists():
        save_settings(settings, args.settings)
        print("Saved %s" % args.settings)
    else:
        print("No changes to %s (kept as is, comments included)" % args.settings)

    # ---- file locations -> paths.yaml (created with defaults the first time)
    if not Path(args.paths).exists():
        _write_default_paths(args.paths, PATH_DEFAULTS)
        print("Created %s (file and folder locations; edit it to move audit/log files)" % args.paths)

    ask_policy(args.rules)
    if prompts.ask_yes_no("Test the connection now?", True):
        args.server = args.database = None
        args.connection = name
        return cmd_test_connection(args)
    return 0


def _write_default_paths(path, defaults):
    lines = ["# File and folder locations. Relative paths are relative to the project folder.",
             "# Absolute paths (e.g. D:\\deid\\audit) and %ENV% variables are allowed."]
    lines += ["%s: %s" % (k, v) for k, v in defaults.items()]
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text("\n".join(lines) + "\n", encoding="utf-8")


def cmd_connections(args):
    """List the database connections in connections.yaml."""
    from deid.config import load_connections
    if not Path(args.connections).exists():
        print("No %s yet. Add a connection with: python main.py configure" % args.connections)
        return 1
    default, conns = load_connections(args.connections)
    for n, c in conns.items():
        print("  %s %-16s %s / %s  (auth=%s)" % ("*" if n == default else " ", n, c["server"], c["database"], c["auth"]))
    print("  (* = default; choose another with --connection NAME)")
    return 0


def cmd_policy(args):
    ask_policy(args.rules)
    if Path(args.rules).exists():
        try:
            load_rules(args.rules)
        except ConfigError as exc:
            if "defines no tables" not in str(exc):
                raise
    return 0
