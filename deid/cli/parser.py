"""Command-line parser and entry point (routing only; commands live in the *_commands modules)."""

from __future__ import annotations

import argparse
import logging
import sys

from .. import __version__
from ..config import (
    ConfigError,
    load_paths,
)
from ..database.connection import DatabaseError
from ..masking import MASKERS, MaskerError
from .common import DEFAULT_CONNECTIONS, DEFAULT_PATHS, DEFAULT_SETTINGS
from .db_commands import (
    cmd_audit_report,
    cmd_discover,
    cmd_dry_run,
    cmd_import_csv,
    cmd_recommend,
    cmd_run,
    cmd_validate,
    cmd_wizard,
)
from .file_commands import cmd_files_discover, cmd_files_run, cmd_files_validate
from .setup_commands import (
    cmd_configure,
    cmd_connections,
    cmd_genkey,
    cmd_key_fingerprint,
    cmd_policy,
    cmd_test_connection,
)
from .refresh_command import cmd_refresh
from .tool_commands import cmd_list_types, cmd_preview, cmd_test_vectors

log = logging.getLogger("deid")


def build_parser():
    p = argparse.ArgumentParser(prog="pythondeid", description="Deterministic SQL Server de-identification")
    p.add_argument("--version", action="version", version=__version__)
    p.add_argument("--settings", default=DEFAULT_SETTINGS, help="run settings YAML (default config/settings.yaml)")
    p.add_argument("--connections", default=DEFAULT_CONNECTIONS,
                   help="database connections YAML (default config/connections.yaml)")
    p.add_argument("-c", "--connection", help="connection name from connections.yaml (default: its 'default')")
    p.add_argument("--paths", default=DEFAULT_PATHS, help="file locations YAML (default config/paths.yaml)")
    p.add_argument("--rules", help="rules YAML (default: rules_file in paths.yaml)")
    p.add_argument("-p", "--profile", help="masking profile from config/profiles (e.g. internal, external)")
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

    rf = sub.add_parser("refresh", help="unattended run for schedulers (Stonebranch / SQL Agent): validate, "
                                        "dry-run, mask, optional files; exit codes + JSON result")
    rf.add_argument("--with-files", action="store_true", help="also de-identify files (file_rules.yaml)")
    rf.add_argument("--resume", metavar="RUN_ID", help="continue a PARTIAL run")
    rf.add_argument("--force", action="store_true", help="mask even if an earlier run masked this database")
    rf.add_argument("--result-file", help="JSON result path (default: run_results_dir in paths.yaml)")
    rf.set_defaults(func=cmd_refresh)

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
