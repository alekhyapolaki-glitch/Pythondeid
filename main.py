#!/usr/bin/env python
"""pythondeid command line.

Typical flow:
    python main.py genkey                 # once; store the key in DEID_SECRET_KEY
    python main.py test-connection
    python main.py discover               # table structure -> config/discovered_schema.csv
    python main.py wizard                 # or: edit the CSV, then import-csv
    python main.py validate
    python main.py dry-run
    python main.py run
    python main.py audit-report
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import sys
from pathlib import Path

from deid import __version__, prompts
from deid.config import (PROJECT_ROOT, ConfigError, load_paths, load_rules, load_settings, rules_from_csv, save_rules,
                         save_settings)
from deid.db import ConnectionFactory, DatabaseError, server_info
from deid.maskers import ALGORITHM_VERSION, MASKERS, KeyRing, MaskerError, build_maskers, create_masker

log = logging.getLogger("deid")

# Config files (relative to the project folder, so the tool works from any current directory):
DEFAULT_SETTINGS = str(PROJECT_ROOT / "config" / "settings.yaml")        # how it runs
DEFAULT_CONNECTIONS = str(PROJECT_ROOT / "config" / "connections.yaml")  # database connections (this machine)
DEFAULT_PATHS = str(PROJECT_ROOT / "config" / "paths.yaml")              # file and folder locations
# The rules file location comes from paths.yaml (rules_file) unless --rules is given.


# =============================================================================
# helpers
# =============================================================================
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
    from deid.logging_setup import setup_logging
    return setup_logging(settings.logging.get("level", "INFO"), settings.logging.get("dir", "logs"), name)


def _engine(args, settings, rules):
    from deid.engine import Engine
    factory = ConnectionFactory(settings.database, interactive=not args.yes)
    return Engine(settings, rules, _keyring(settings), factory)


# =============================================================================
# commands
# =============================================================================
def cmd_genkey(args):
    key = KeyRing.generate()
    print("New secret key (store it in a vault; every run must use the SAME key for consistent masking):\n")
    print("  " + key + "\n")
    print("Windows (current session):   set DEID_SECRET_KEY=" + key)
    print("Windows (persist for user):  setx DEID_SECRET_KEY \"" + key + "\"")
    print("PowerShell:                  $env:DEID_SECRET_KEY=\"" + key + "\"")
    print("Linux/macOS:                 export DEID_SECRET_KEY='" + key + "'")
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
    from deid.config import (DEFAULT_CONNECTION, DEFAULT_PATHS as PATH_DEFAULTS, load_connections,
                             save_connection)
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


def cmd_policy(args):
    ask_policy(args.rules)
    if Path(args.rules).exists():
        try:
            load_rules(args.rules)
        except ConfigError as exc:
            if "defines no tables" not in str(exc):
                raise
    return 0


def cmd_discover(args):
    from deid.discovery import export_schema_csv
    from deid.schema import SchemaCatalog
    settings = _settings(args)
    conn = ConnectionFactory(settings.database, interactive=not args.yes).connect(autocommit=True)
    catalog = SchemaCatalog.load(conn, args.schema or None)
    conn.close()
    n = export_schema_csv(catalog, args.out, args.only_suggested)
    print("Wrote %d column(s) from %d table(s) to %s" % (n, len(catalog.tables), args.out))
    print("Fill in 'mask_type' (and optionally 'domain', 'params_json'), then run: python main.py import-csv %s" % args.out)
    return 0


def cmd_import_csv(args):
    rules = rules_from_csv(args.csv)
    if Path(args.rules).exists() and not args.yes and not prompts.ask_yes_no("Overwrite %s?" % args.rules, False):
        return 1
    save_rules(rules, args.rules, "Generated from %s by pythondeid %s" % (args.csv, __version__))
    print("Wrote %d table(s), %d domain(s) to %s" % (len(rules.tables), len(rules.domains), args.rules))
    return 0


def cmd_wizard(args):
    from deid.discovery import run_wizard
    from deid.schema import SchemaCatalog
    settings = _settings(args)
    conn = ConnectionFactory(settings.database, interactive=True).connect(autocommit=True)
    catalog = SchemaCatalog.load(conn)
    conn.close()
    existing = None
    if Path(args.rules).exists() and prompts.ask_yes_no("Start from the existing %s?" % args.rules, True):
        existing = load_rules(args.rules)
    policy = ask_policy(args.rules) if Path(args.rules).exists() else None
    if policy is None:
        from deid.config import POLICY_OPTIONS
        policy = current_policy(args.rules)
        print("\n=== Masking policy ===")
        for key, (_, _, allowed, question) in POLICY_OPTIONS.items():
            policy[key] = prompts.choose(question, list(allowed), policy[key])
    rules = run_wizard(catalog, existing, policy)
    if not rules.tables:
        print("Nothing selected; rules not written.")
        return 1
    out = prompts.ask("Save rules to", args.rules)
    save_rules(rules, out, "Generated by the pythondeid wizard %s" % __version__)
    print("Saved %s. Next: python main.py validate" % out)
    return 0


def _plan(args):
    settings = _settings(args)
    _setup_logging(settings)
    rules = load_rules(args.rules)
    engine = _engine(args, settings, rules)
    info = engine.connect()
    plan = engine.plan()
    return settings, rules, engine, info, plan


def cmd_validate(args):
    _, _, engine, _, plan = _plan(args)
    try:
        print(plan.describe())
        print("\nPlan is VALID" if plan.ok else "\nPlan has %d error(s)" % len(plan.errors))
        return 0 if plan.ok else 2
    finally:
        engine.close()


def cmd_dry_run(args):
    _, _, engine, info, plan = _plan(args)
    try:
        print(plan.describe())
        if not plan.ok:
            return 2
        result = engine.execute(plan, dry_run=True, info=info)
        _print_result(result)
        return 0 if result["status"] == "DRY_RUN_OK" else 2
    finally:
        engine.close()


def cmd_run(args):
    settings, rules, engine, info, plan = _plan(args)
    try:
        print(plan.describe())
        if not plan.ok:
            print("\nFix the errors above (python main.py validate) before running.")
            return 2
        if not args.resume:
            prior = [r for r in engine.previous_runs()
                     if r["mode"] == "run" and r["rules_hash"] == rules.content_hash and r["status"] != "FAILED"]
            if prior and not args.force:
                r = prior[0]
                print("\nRun %s (status %s, %s) already applied these rules to this database. Masking masked data "
                      "again would break consistency." % (r["run_id"], r["status"], r["started_at"]))
                if r["status"] in ("PARTIAL", "RUNNING"):
                    print("Resume it with: python main.py run --resume %s" % r["run_id"])
                print("Use --force only on a freshly restored copy.")
                return 3
        if not args.yes:
            print("\nTarget: server=%s database=%s login=%s" % (info["server"], info["database"], info["login"]))
            print("This UPDATES data in place and cannot be undone.")
            if not prompts.ask_yes_no("Is this a NON-production copy and do you have a verified backup?", False):
                print("Aborted.")
                return 1
            dry = _last_dry_run(settings, rules, info)
            if dry:
                print("Found passing dry-run %s for these rules." % dry)
            elif not prompts.ask_yes_no("No passing dry-run found for these rules/database. Continue anyway?", False):
                print("Run 'python main.py dry-run' first.")
                return 1
            if not prompts.confirm_phrase("Final confirmation.", info["database"]):
                print("Aborted.")
                return 1
        result = engine.execute(plan, dry_run=False, info=info, resume_from=args.resume)
        _print_result(result)
        return 0 if result["status"] == "SUCCEEDED" else 2
    finally:
        engine.close()


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


def _print_result(result):
    print("\nRun %s finished: %s" % (result["run_id"], result["status"]))
    print("  tables completed: %d / %d" % (result["tables_completed"], result["tables"]))
    print("  rows updated:     %d" % result["rows_updated"])
    for f in result["failures"]:
        print("  FAILURE: %s" % f)
    print("  audit files:      %s" % result["audit_dir"])


def cmd_audit_report(args):
    out_dir = Path(_load(args).audit.get("output_dir", "audit"))
    if args.run_id:
        p = out_dir / args.run_id / "summary.json"
        if not p.exists():
            print("No audit summary at %s" % p)
            return 1
        data = json.loads(p.read_text(encoding="utf-8"))
        cols = data.pop("columns", [])
        for k, v in data.items():
            print("  %-16s %s" % (k, v))
        print("\n  %-40s %-16s %-10s %12s %12s %12s %10s" % ("column", "mask", "status", "non-null", "distinct",
                                                            "dist.after", "updated"))
        for c in cols:
            print("  %-40s %-16s %-10s %12s %12s %12s %10s" % (
                "%s.%s.%s" % (c["schema_name"], c["table_name"], c["column_name"])[:40], c["mask_type"], c["status"],
                c["rows_non_null_before"], c["distinct_before"], c["distinct_after"], c["rows_updated"]))
        return 0
    runs = sorted(out_dir.glob("*/summary.json"), reverse=True)
    if not runs:
        print("No runs recorded in %s" % out_dir)
    for p in runs[: args.limit]:
        d = json.loads(p.read_text(encoding="utf-8"))
        print("  %-24s %-8s %-15s %s  %s" % (d.get("run_id"), d.get("mode"), d.get("status"), d.get("started_at"),
                                            d.get("database", "")))
    return 0


def cmd_preview(args):
    """Mask sample values offline (no database) to check algorithms and consistency."""
    settings = _load(args)
    keyring = _keyring(settings)
    params = json.loads(args.params) if args.params else {}
    if args.domain and not args.type:
        rules = load_rules(args.rules)
        if args.domain not in rules.domains:
            print("Domain %s not in %s" % (args.domain, args.rules))
            return 1
        m = build_maskers(rules.domains.values(), keyring)[args.domain]
    elif args.type:
        m = create_masker(args.type, args.domain or args.type, keyring, params)
    else:
        print("Give --type (one of %s) or --domain from the rules file" % ", ".join(sorted(MASKERS)))
        return 1
    for v in args.values:
        print("  %-30s -> %s" % (v, m.mask(v, args.entity)))
    return 0


# =============================================================================
# CSV / Excel file de-identification
# =============================================================================
def _file_rules(args, settings, rules):
    from deid.files import load_file_rules
    return load_file_rules(args.file_rules or settings.paths["file_rules"], rules)


def _check_key_pin(settings, keyring):
    pinned = (settings.security.get("expected_key_fingerprint") or "").strip()
    if pinned and pinned != keyring.fingerprint():
        raise ConfigError("DEID_SECRET_KEY does not match security.expected_key_fingerprint (%s, got %s)"
                          % (pinned, keyring.fingerprint()))


def cmd_files_discover(args):
    """Read the headers of the files in the input folder and draft file_rules.yaml with suggested domains."""
    from deid.files import draft_file_rules
    settings = _load(args)
    rules = load_rules(args.rules)
    input_dir = args.input or settings.paths["file_input_dir"]
    if not Path(input_dir).is_dir():
        print("Input folder %s does not exist. Put your CSV/Excel files there (file_input_dir in paths.yaml) "
              "or pass --input FOLDER." % input_dir)
        return 1
    out = args.out or args.file_rules or settings.paths["file_rules"]
    if Path(out).exists() and not args.yes and not prompts.ask_yes_no("Overwrite %s?" % out, False):
        return 1
    text, n = draft_file_rules(input_dir, rules)
    Path(out).parent.mkdir(parents=True, exist_ok=True)
    Path(out).write_text(text, encoding="utf-8")
    print("Drafted %d file entr%s from the headers in %s -> %s" % (n, "y" if n == 1 else "ies", input_dir, out))
    print("Review it (domains are guesses from header names), then: python main.py files-validate")
    return 0


def cmd_files_validate(args):
    """Check the file rules against the actual files: matches, sheets, columns, domains."""
    from deid.files import find_inputs, read_headers
    settings = _load(args)
    rules = load_rules(args.rules)
    fr = _file_rules(args, settings, rules)
    input_root = Path(args.input or settings.paths["file_input_dir"])
    matched, unmatched = find_inputs(str(input_root), fr)
    problems = 0
    print("File rules: %s (%d entr%s)" % (fr.source_path, len(fr.files), "y" if len(fr.files) == 1 else "ies"))
    for path, rule in matched:
        heads = read_headers(path, int(rule.excel.get("header_row", 1)), rule.csv)
        sheets = [s for s in heads if s] if not rule.sheets else rule.sheets
        print("  %s  -> rule '%s'" % (path.name, rule.name))
        for sheet in (sheets or [""]):
            header = {h.lower() for h in heads.get(next((k for k in heads if k.lower() == sheet.lower()), sheet), [])}
            if sheet and not any(k.lower() == sheet.lower() for k in heads):
                print("      sheet %s: NOT FOUND" % sheet)
                problems += 1
                continue
            for c in rule.columns:
                dom = rules.domains[c.domain]
                found = c.name.lower() in header and (not c.entity_column or c.entity_column.lower() in header)
                setting = ", ".join("%s=%s" % (k, dom.params[k]) for k in ("mode", "method") if k in dom.params)
                print("      %s%-28s -> %-16s %s%s" % ((sheet + ": ") if sheet else "", c.name, c.domain,
                                                   ("[%s] " % setting) if setting else "",
                                                   "" if found else "  <-- NOT FOUND"))
                problems += 0 if found else 1
    for path in unmatched:
        print("  %s  (no matching rule; will be skipped)" % path.name)
    if not matched:
        print("No files in %s match the rules." % input_root)
        return 2
    print("\nFile rules are VALID" if not problems else "\n%d problem(s) found" % problems)
    return 0 if not problems else 2


def cmd_files_run(args):
    """De-identify CSV/Excel files into the output folder (originals are never modified)."""
    from dataclasses import asdict
    from deid.audit import AuditTrail, new_run_id
    from deid.files import FileDeidentifier, FileRuleError, find_inputs, output_path_for
    settings = _load(args)
    _setup_logging(settings)
    rules = load_rules(args.rules)
    keyring = _keyring(settings)
    _check_key_pin(settings, keyring)
    fr = _file_rules(args, settings, rules)
    input_root = Path(args.input or settings.paths["file_input_dir"])
    output_dir = Path(args.output_dir or settings.paths["file_output_dir"])
    matched, unmatched = find_inputs(str(input_root), fr)
    if not matched:
        print("No files in %s match %s" % (input_root, fr.source_path))
        return 2
    print("%s %d file(s): %s -> %s" % ("Dry run of" if args.dry_run else "De-identifying", len(matched),
                                        input_root, output_dir))
    for path, rule in matched:
        print("  %s -> %s  [rule %s: %s]" % (path.name, output_path_for(path, input_root, output_dir, rule).name,
                                            rule.name, ", ".join("%s->%s" % (c.name, c.domain) for c in rule.columns)))
    for path in unmatched:
        print("  %s (no matching rule, skipped)" % path.name)
    if not args.dry_run and not args.yes and not prompts.ask_yes_no(
            "Write the de-identified copies to %s? (originals are not changed)" % output_dir, True):
        print("Aborted.")
        return 1
    run_id = new_run_id()
    audit = AuditTrail(settings.audit, run_id, None)
    audit.start_run("files-dry-run" if args.dry_run else "files", {
        "rules_file": str(rules.source_path), "rules_hash": rules.content_hash,
        "file_rules": str(fr.source_path), "file_rules_hash": fr.content_hash,
        "key_fingerprint": keyring.fingerprint(), "tool_version": __version__,
        "input": str(input_root), "output": str(output_dir), "files_planned": len(matched),
    })
    from deid.advisor import resolve_workers
    deid = FileDeidentifier(rules, fr, keyring, resolve_workers(settings.execution.get("workers", "auto")))
    ok = failed = 0
    for path, rule in matched:
        try:
            res = deid.process(path, input_root, output_dir, rule, args.dry_run, args.overwrite)
            ok += 1
            print("  OK   %s: %d rows, masked cells %s%s" % (path.name, res.rows, res.masked_cells,
                                                         ("; " + res.message) if res.message else ""))
            audit.file_result(asdict(res))
        except (FileRuleError, MaskerError, OSError, ValueError, csv.Error) as exc:
            failed += 1
            print("  FAIL %s: %s" % (path.name, exc))
            audit.event("ERROR", str(exc), str(path))
            audit.file_result({"rule": rule.name, "input_path": str(path), "status": "FAILED", "message": str(exc)})
    deid.close()
    status = ("DRY_RUN_OK" if args.dry_run else "SUCCEEDED") if not failed else ("PARTIAL" if ok else "FAILED")
    audit.end_run(status, "%d ok, %d failed" % (ok, failed), ok, 0)
    print("\nRun %s: %s (%d ok, %d failed). Audit: %s" % (run_id, status, ok, failed, audit.dir))
    return 0 if not failed else 2


def cmd_list_types(args):
    from deid.advisor import TYPE_GUIDE
    for name in sorted(MASKERS):
        cls = MASKERS[name]
        guide = TYPE_GUIDE.get(name, {})
        print("%s\n    %s" % (name, cls.description))
        if cls.default_params:
            print("    params:        %s" % cls.default_params)
        if cls.format_params:
            print("    column-level:  %s (format only, may differ per column)" % ", ".join(sorted(cls.format_params)))
        if guide:
            print("    input types:   %s" % guide["input"])
            print("    output types:  %s" % guide["output"])
            if guide.get("notes"):
                print("    notes:         %s" % guide["notes"])
    return 0


def cmd_key_fingerprint(args):
    settings = _load(args)
    fp = _keyring(settings).fingerprint()
    print("Key fingerprint: %s  (algorithm version %d)" % (fp, ALGORITHM_VERSION))
    print("Pin it on every server in settings.yaml:  security.expected_key_fingerprint: %s" % fp)
    return 0


SAMPLE_INPUTS = {
    "email": ["alice@example.org", "Bob.Smith@Corp.COM"],
    "ssn": ["123-45-6789", "123456789", "078051120"],
    "account_number": ["ACC-000123-01", "0000012345", "12345"],
    "fpe": ["AB-12345", "0000012345"],
    "credit_card": ["4111111111111111", "5500-0000-0000-0004"],
    "phone": ["(555) 123-4567", "+1 555 987 6543"],
    "first_name": ["John", "MARIA"], "last_name": ["Smith", "garcia"], "full_name": ["John Q Public"],
    "street_address": ["12 High St"], "city": ["Boston"], "zip": ["02118", "80202-1234"],
    "date_shift": ["1980-04-12", "2024-01-05T10:15:00.000"], "redact": ["secret"], "nullify": ["x"],
    "hash": ["abc"], "free_text": ["Call 555-123-4567 or mail a.b@corp.com; SSN 123-45-6789"],
}


def cmd_test_vectors(args):
    """Write (or check) known-answer masks so every server/environment can prove it masks identically."""

    settings = _load(args)
    keyring = _keyring(settings)
    rules = load_rules(args.rules)
    maskers = build_maskers(rules.domains.values(), keyring)
    rows = []
    for name, d in sorted(rules.domains.items()):
        for v in SAMPLE_INPUTS.get(d.type, ["sample-123"]):
            for entity in ([None, "42"] if d.type == "date_shift" else [None]):
                try:
                    out = maskers[name].mask(v, entity)
                except MaskerError as exc:
                    out = "ERROR: %s" % exc
                rows.append({"domain": name, "type": d.type, "input": v, "entity": entity or "",
                             "masked": "<NULL>" if out is None else out})
    header = {"key_fingerprint": keyring.fingerprint(), "rules_hash": rules.content_hash,
              "algorithm_version": ALGORITHM_VERSION}
    if args.check:
        with open(args.check, newline="", encoding="utf-8") as fh:
            meta = json.loads(fh.readline().lstrip("# ").strip())
            expected = list(csv.DictReader(fh))
        problems = ["%s: file=%s here=%s" % (k, meta.get(k), header[k]) for k in header if meta.get(k) != header[k]]
        exp = {(r["domain"], r["input"], r["entity"]): r["masked"] for r in expected}
        got = {(r["domain"], r["input"], r["entity"]): r["masked"] for r in rows}
        diffs = [k for k in exp if got.get(k) != exp[k]]
        for p_ in problems:
            print("  MISMATCH %s" % p_)
        for k in diffs[:20]:
            print("  DIFF %s %r: expected %r got %r" % (k[0], k[1], exp[k], got.get(k)))
        if problems or diffs:
            print("NOT consistent with %s (%d value differences)" % (args.check, len(diffs)))
            return 2
        print("Consistent: %d test vectors match %s" % (len(exp), args.check))
        return 0
    with open(args.out, "w", newline="", encoding="utf-8") as fh:
        fh.write("# " + json.dumps(header) + "\n")
        w = csv.DictWriter(fh, fieldnames=["domain", "type", "input", "entity", "masked"])
        w.writeheader()
        w.writerows(rows)
    print("Wrote %d test vectors to %s (contains only synthetic sample values)." % (len(rows), args.out))
    print("On every other server run: python main.py test-vectors --check %s" % args.out)
    return 0


def cmd_recommend(args):
    """Column type/format recommendations, batch sizes for big tables and database readiness."""

    from deid.advisor import column_recommendations, database_health, estimate_log_mb
    settings, _rules, engine, _info, plan = _plan(args)
    try:
        print("\n=== Tables: size and update strategy ===")
        print("  %-36s %12s %10s %8s  %-8s %10s %8s" % ("table", "rows", "MB", "B/row", "strategy", "batch", "batches"))
        largest_single = 0
        for tp in plan.tables:
            ti = tp.info
            if tp.strategy == "chunked":
                chunks = -(-ti.row_count // max(tp.batch_size, 1)) if ti.row_count else 0
                batch, nb = str(tp.batch_size), str(chunks)
            else:
                batch, nb = "-", "1"
                largest_single = max(largest_single, estimate_log_mb(ti))
            print("  %-36s %12d %10.1f %8d  %-8s %10s %8s" % (
                tp.fqn[:36], ti.row_count, ti.data_bytes / 1048576.0, ti.avg_row_bytes, tp.strategy, batch, nb))
            for n in tp.notes:
                print("        %s" % n)
        print("  (batch_size=auto targets ~%d MB rewritten per committed batch; tune batching.* in settings.yaml)"
              % settings.batching["target_batch_mb"])
        health = database_health(engine.read, largest_single, sum(t.info.row_count for t in plan.tables))
        print("\n=== Database readiness ===")
        for k, v in health.facts.items():
            print("  %-30s %s" % (k, v))
        for a in health.advice:
            print("  * " + a)
        print("\n=== Columns: input/output types and formats (sample of %d rows each) ===" % args.sample)
        recs = column_recommendations(plan, engine.read, args.sample)
        for r in recs:
            print("  %s.%s  %s -> %s [%s]" % (r["table"], r["column"], r["actual_type"], r["output_type"], r["mask_type"]))
            if r["sampled"]:
                print("      sample: len %s-%s, max digits %s, all-digits %s%%, leading zero %s%%, formats: %s" % (
                    r["min_len"], r["max_len"], r["max_digits"], r["all_digits_pct"], r["leading_zero_pct"],
                    r["top_patterns"]))
            print("      recommended output: %s" % r["recommended_types"])
            if r["advice"]:
                print("      ADVICE: %s" % r["advice"])
        for w in plan.warnings:
            print("WARNING: " + w)
        for e in plan.errors:
            print("ERROR:   " + e)
        if args.out:
            with open(args.out, "w", newline="", encoding="utf-8") as fh:
                w = csv.DictWriter(fh, fieldnames=list(recs[0].keys()) if recs else ["table"])
                w.writeheader()
                w.writerows(recs)
            print("\nWrote %s" % args.out)
        return 0 if plan.ok else 2
    finally:
        engine.close()


# =============================================================================
# argument parsing
# =============================================================================
def build_parser():
    p = argparse.ArgumentParser(prog="pythondeid", description="Deterministic SQL Server de-identification")
    p.add_argument("--version", action="version", version=__version__)
    p.add_argument("--settings", default=DEFAULT_SETTINGS, help="run settings YAML (default config/settings.yaml)")
    p.add_argument("--connections", default=DEFAULT_CONNECTIONS,
                   help="database connections YAML (default config/connections.yaml)")
    p.add_argument("-c", "--connection", help="connection name from connections.yaml (default: its 'default')")
    p.add_argument("--paths", default=DEFAULT_PATHS, help="file locations YAML (default config/paths.yaml)")
    p.add_argument("--rules", help="rules YAML (default: rules_file in paths.yaml)")
    p.add_argument("--server", help="override database.server")
    p.add_argument("--database", help="override database.database")
    p.add_argument("-y", "--yes", action="store_true", help="non-interactive: no questions (use with care)")
    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("genkey", help="generate a secret masking key").set_defaults(func=cmd_genkey)
    sub.add_parser("configure", help="answer questions: connection, run settings, masking policy").set_defaults(
        func=cmd_configure)
    sub.add_parser("connections", help="list database connections").set_defaults(func=cmd_connections)
    sub.add_parser("policy", help="choose full vs last4 (SSN, account, card) and name method").set_defaults(
        func=cmd_policy)
    sub.add_parser("test-connection", help="check database connectivity").set_defaults(func=cmd_test_connection)
    sub.add_parser("list-types", help="list mask types and parameters").set_defaults(func=cmd_list_types)

    d = sub.add_parser("discover", help="export table structure + PII suggestions to CSV")
    d.add_argument("--schema", action="append", help="limit to schema (repeatable)")
    d.add_argument("--out", help="CSV to write (default: discovery_csv in paths.yaml)")
    d.add_argument("--only-suggested", action="store_true", help="only columns that look like PII")
    d.set_defaults(func=cmd_discover)

    i = sub.add_parser("import-csv", help="convert an edited discovery CSV into the rules YAML")
    i.add_argument("csv")
    i.set_defaults(func=cmd_import_csv)

    sub.add_parser("wizard", help="interactive questions to build the rules YAML").set_defaults(func=cmd_wizard)
    sub.add_parser("validate", help="check rules against the live schema").set_defaults(func=cmd_validate)
    sub.add_parser("dry-run", help="mask in memory, validate every value, change nothing").set_defaults(func=cmd_dry_run)

    r = sub.add_parser("run", help="de-identify the database in place")
    r.add_argument("--resume", metavar="RUN_ID", help="continue an interrupted/partial run")
    r.add_argument("--force", action="store_true", help="allow re-running rules already applied")
    r.set_defaults(func=cmd_run)

    a = sub.add_parser("audit-report", help="show audit results")
    a.add_argument("--run-id")
    a.add_argument("--limit", type=int, default=20)
    a.set_defaults(func=cmd_audit_report)

    pv = sub.add_parser("preview", help="mask sample values offline")
    pv.add_argument("values", nargs="+")
    pv.add_argument("--type", choices=sorted(MASKERS))
    pv.add_argument("--domain", help="domain name (uses its definition from the rules file if --type is omitted)")
    pv.add_argument("--params", help="JSON parameters, e.g. '{\"mode\": \"last4\"}'")
    pv.add_argument("--entity", help="person id for date_shift with shift_by: entity")
    pv.set_defaults(func=cmd_preview)

    sub.add_parser("key-fingerprint", help="print the key fingerprint to pin on every server").set_defaults(
        func=cmd_key_fingerprint)

    tv = sub.add_parser("test-vectors", help="write/check known-answer masks to prove cross-server consistency")
    tv.add_argument("--out", help="CSV to write (default: test_vectors in paths.yaml)")
    tv.add_argument("--check", metavar="CSV", help="verify this environment reproduces a vectors file")
    tv.set_defaults(func=cmd_test_vectors)

    fd = sub.add_parser("files-discover", help="draft file_rules.yaml from the headers of CSV/Excel input files")
    fd.add_argument("--input", help="folder with input files (default: file_input_dir in paths.yaml)")
    fd.add_argument("--out", help="where to write the draft (default: file_rules in paths.yaml)")
    fd.add_argument("--file-rules", help=argparse.SUPPRESS)
    fd.set_defaults(func=cmd_files_discover)

    fv = sub.add_parser("files-validate", help="check file rules against the input files (headers, sheets, domains)")
    fv.add_argument("--input", help="file or folder (default: file_input_dir in paths.yaml)")
    fv.add_argument("--file-rules", help="file rules YAML (default: file_rules in paths.yaml)")
    fv.set_defaults(func=cmd_files_validate)

    fr = sub.add_parser("files-run", help="write de-identified copies of CSV/Excel files")
    fr.add_argument("--input", help="file or folder (default: file_input_dir in paths.yaml)")
    fr.add_argument("--output-dir", help="output folder (default: file_output_dir in paths.yaml)")
    fr.add_argument("--file-rules", help="file rules YAML (default: file_rules in paths.yaml)")
    fr.add_argument("--dry-run", action="store_true", help="read and mask everything, write nothing")
    fr.add_argument("--overwrite", action="store_true", help="replace existing output files")
    fr.set_defaults(func=cmd_files_run)

    rc = sub.add_parser("recommend", help="data type, format and batch-size recommendations for the rules")
    rc.add_argument("--sample", type=int, default=5000, help="rows sampled per column for format profiling")
    rc.add_argument("--out", help="also write the column recommendations to this CSV")
    rc.set_defaults(func=cmd_recommend)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        paths = load_paths(args.paths)
        if not args.rules:
            args.rules = paths["rules_file"]
        if getattr(args, "out", "unset") is None and args.command in ("discover", "test-vectors"):
            args.out = paths["discovery_csv" if args.command == "discover" else "test_vectors"]
        return args.func(args)
    except (ConfigError, MaskerError, DatabaseError) as exc:
        print("ERROR: %s" % exc, file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\nInterrupted. If a run was in progress, resume it with: python main.py run --resume <run_id>",
              file=sys.stderr)
        return 130
    except Exception as exc:
        from deid.engine import PlanError
        if isinstance(exc, PlanError):
            print("ERROR: %s" % exc, file=sys.stderr)
            return 2
        log.exception("Unexpected error")
        print("UNEXPECTED ERROR: %s (details in the log file)" % exc, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
