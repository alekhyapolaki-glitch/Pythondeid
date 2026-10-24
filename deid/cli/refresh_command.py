"""Unattended masking run for schedulers (Stonebranch, SQL Server Agent):

    validate -> (already masked?) -> dry-run -> mask -> [CSV/Excel files]

No questions are asked.  The outcome is reported three ways: the process exit code, a final
`DEID_RESULT ...` line on stdout, and a JSON result file (paths.yaml -> run_results_dir) that later
scheduler tasks (e.g. extracts to vendors) can check before they run.

Exit codes
    0  SUCCEEDED        database (and files, if requested) de-identified
    2  INVALID          rules/plan or dry-run found problems; nothing was changed
    3  ALREADY_MASKED   this database was already masked by an earlier run (restore a fresh copy)
    4  PARTIAL          some tables were masked; fix the cause and run with --resume <run_id>
    5  FAILED           masking failed before any data was committed
    6  FILES_FAILED     database succeeded, but one or more files failed
    7  LOCKED           another masking run is in progress on this database
    10 CONFIG_ERROR     configuration problem (rules, profile, settings, key)
    11 CONNECTION_ERROR could not connect to SQL Server
    1  UNEXPECTED       unexpected error (see the log file)
"""

from __future__ import annotations

import datetime as _dt
import json
import logging
import time
from pathlib import Path
from typing import Any, Dict, List

from .. import __version__
from ..config import ConfigError
from ..database.connection import DatabaseError
from ..masking import MaskerError
from .common import _check_key_pin, _engine, _keyring, _rules, _settings, _setup_logging

log = logging.getLogger("deid.refresh")

EXIT_CODES = {
    "SUCCEEDED": 0, "INVALID": 2, "ALREADY_MASKED": 3, "PARTIAL": 4, "FAILED": 5, "FILES_FAILED": 6,
    "LOCKED": 7, "CONFIG_ERROR": 10, "CONNECTION_ERROR": 11, "UNEXPECTED": 1,
}


class _Outcome(Exception):
    def __init__(self, status: str, message: str):
        super().__init__(message)
        self.status = status


def cmd_refresh(args) -> int:
    args.yes = True  # unattended: never prompt (a password prompt would hang the scheduler)
    started = time.time()
    result: Dict[str, Any] = {
        "tool": "pythondeid", "tool_version": __version__, "command": "refresh",
        "profile": args.profile or "", "connection": args.connection or "", "started_at": _now(),
        "steps": [],
    }
    settings = None
    try:
        try:
            settings = _settings(args)
            _setup_logging(settings, "deid")
            rules = _rules(args, settings)
            keyring = _keyring(settings)
            _check_key_pin(settings, keyring)
        except (ConfigError, MaskerError) as exc:
            raise _Outcome("CONFIG_ERROR", str(exc)) from None
        result.update(connection=settings.connection_name, rules_hash=rules.content_hash,
                      key_fingerprint=keyring.fingerprint(), policy=rules.policy)
        _run_database(args, settings, rules, result)
        if args.with_files:
            _run_files(args, settings, rules, keyring, result)
        status, message = "SUCCEEDED", "de-identification completed"
    except _Outcome as out:
        status, message = out.status, str(out)
    except Exception as exc:
        log.exception("Unexpected error during refresh")
        status, message = "UNEXPECTED", "%s: %s" % (exc.__class__.__name__, exc)
    result.update(status=status, exit_code=EXIT_CODES[status], message=message, ended_at=_now(),
                  seconds=round(time.time() - started, 1))
    path = _write_result(args, settings, result)
    print("DEID_RESULT status=%s exit_code=%d profile=%s run_id=%s result_file=%s"
          % (status, result["exit_code"], result["profile"] or "-", result.get("run_id", "-"), path))
    if status != "SUCCEEDED":
        print("DEID_MESSAGE %s" % message)
    return result["exit_code"]


def _step(result: Dict[str, Any], name: str, **data) -> None:
    result["steps"].append(dict({"step": name, "at": _now()}, **data))
    log.info("refresh step %s: %s", name, data)


def _run_database(args, settings, rules, result: Dict[str, Any]) -> None:
    from ..engine import PlanError, RunLocked
    engine = _engine(args, settings, rules)
    try:
        try:
            info = engine.connect()
        except DatabaseError as exc:
            raise _Outcome("CONNECTION_ERROR", str(exc)) from None
        result.update(server=info["server"], database=info["database"], login=info["login"])
        plan = engine.plan()
        _step(result, "validate", ok=plan.ok, errors=plan.errors[:20], warnings=len(plan.warnings),
              tables=len(plan.tables))
        if not plan.ok:
            raise _Outcome("INVALID", "plan has %d error(s): %s" % (len(plan.errors), "; ".join(plan.errors[:3])))
        if not args.resume:
            prior = [r for r in engine.previous_runs() if r["mode"] == "run" and r["status"] != "FAILED"]
            if prior and not args.force:
                raise _Outcome("ALREADY_MASKED", "database %s was already masked by run %s (%s); restore a fresh "
                               "copy before refreshing" % (info["database"], prior[0]["run_id"], prior[0]["status"]))
        try:
            dry = engine.execute(plan, dry_run=True, info=info)
            _step(result, "dry_run", run_id=dry["run_id"], status=dry["status"], failures=dry["failures"][:20])
            if dry["status"] != "DRY_RUN_OK":
                raise _Outcome("INVALID", "dry run found problems: %s" % "; ".join(dry["failures"][:3]))
            run = engine.execute(plan, dry_run=False, info=info, resume_from=args.resume)
        except RunLocked as exc:
            raise _Outcome("LOCKED", str(exc)) from None
        except PlanError as exc:
            raise _Outcome("CONFIG_ERROR", str(exc)) from None
        result.update(run_id=run["run_id"], rows_updated=run["rows_updated"], audit_dir=run["audit_dir"])
        _step(result, "mask", run_id=run["run_id"], status=run["status"], tables=run["tables"],
              tables_completed=run["tables_completed"], rows_updated=run["rows_updated"],
              failures=run["failures"][:20])
        if run["status"] == "PARTIAL":
            result["resume_run_id"] = run["run_id"]  # for automation: refresh --resume <resume_run_id>
            raise _Outcome("PARTIAL", "masking stopped part-way (%s); fix the cause and rerun with --resume %s"
                           % ("; ".join(run["failures"][:3]), run["run_id"]))
        if run["status"] != "SUCCEEDED":
            raise _Outcome("FAILED", "masking failed: %s" % "; ".join(run["failures"][:3]))
    finally:
        engine.close()


def _run_files(args, settings, rules, keyring, result: Dict[str, Any]) -> None:
    from ..files import find_inputs, load_file_rules
    from .file_commands import run_file_masking
    fr = load_file_rules(settings.paths["file_rules"], rules)
    input_root = Path(settings.paths["file_input_dir"])
    output_dir = Path(settings.paths["file_output_dir"])
    matched, unmatched = find_inputs(str(input_root), fr)
    if not matched:
        _step(result, "files", status="NO_FILES", input=str(input_root))
        return
    files = run_file_masking(settings, rules, keyring, fr, matched, input_root, output_dir, False, True)
    _step(result, "files", run_id=files["run_id"], status=files["status"], ok=files["ok"], failed=files["failed"],
          unmatched=len(unmatched), output=str(output_dir))
    if files["failed"]:
        raise _Outcome("FILES_FAILED", "%d file(s) failed; see %s" % (files["failed"], files["audit_dir"]))


def _write_result(args, settings, result: Dict[str, Any]) -> str:
    if args.result_file:
        path = Path(args.result_file)
    else:
        folder = Path(settings.paths["run_results_dir"]) if settings else Path("audit") / "results"
        stamp = _dt.datetime.now().strftime("%Y%m%dT%H%M%S")
        path = folder / ("refresh_%s_%s.json" % (stamp, result.get("profile") or "default"))
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        text = json.dumps(result, indent=2, default=str)
        path.write_text(text, encoding="utf-8")
        (path.parent / ("latest_%s.json" % (result.get("profile") or "default"))).write_text(text, encoding="utf-8")
    except OSError as exc:
        log.error("Could not write the result file %s: %s", path, exc)
    return str(path)


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


__all__: List[str] = ["EXIT_CODES", "cmd_refresh"]
