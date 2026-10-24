"""CSV/Excel commands: files-discover, files-validate, files-run."""

from __future__ import annotations

import csv
from pathlib import Path

from .. import __version__
from ..config import (
    load_rules,
)
from ..masking import MaskerError
from ..utils import prompts
from .common import _check_key_pin, _keyring, _load, _setup_logging


def _file_rules(args, settings, rules):
    from deid.files import load_file_rules
    return load_file_rules(args.file_rules or settings.paths["file_rules"], rules)


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
                effective = dict(dom.params, **c.overrides)  # the column's own settings win over the domain/policy
                setting = ", ".join("%s=%s" % (k, effective[k]) for k in ("mode", "method") if k in effective)
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
