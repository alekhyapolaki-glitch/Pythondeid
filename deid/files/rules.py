"""file_rules.yaml: which CSV/Excel files, sheets and columns to de-identify, mapped to domains."""

from __future__ import annotations

import fnmatch
import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ..config import ConfigError, Rules, _read_yaml
from ..masking import get_masker_class

CSV_EXT = {".csv", ".txt", ".tsv"}


EXCEL_EXT = {".xlsx", ".xlsm"}


DEFAULTS: Dict[str, Any] = {
    "output_suffix": "_deid",
    "max_file_mb": 2048,              # refuse larger inputs (guards against runaway / zip-bomb style files)
    "on_missing_column": "error",
    "on_value_error": "fail",
    "csv": {"delimiter": ",", "encoding": "utf-8-sig", "quotechar": '"', "max_field_kb": 1024},
    "excel": {"mode": "in_place", "header_row": 1},
}


class FileRuleError(ConfigError):
    pass


@dataclass
class FileColumn:
    name: str
    domain: str
    entity_column: str = ""
    overrides: Dict[str, Any] = field(default_factory=dict)


@dataclass
class FileRule:
    name: str
    pattern: str
    columns: List[FileColumn]
    format: str = ""                     # csv | excel | "" = from the extension
    sheets: List[str] = field(default_factory=list)
    output_suffix: str = "_deid"
    max_file_mb: int = 2048
    on_missing_column: str = "error"
    on_value_error: str = "fail"
    csv: Dict[str, Any] = field(default_factory=dict)
    excel: Dict[str, Any] = field(default_factory=dict)

    def matches(self, relative: str) -> bool:
        rel = relative.replace("\\", "/")
        pat = self.pattern.replace("\\", "/")
        return fnmatch.fnmatch(rel.lower(), pat.lower()) or fnmatch.fnmatch(Path(rel).name.lower(), pat.lower())


@dataclass
class FileRules:
    files: List[FileRule]
    source_path: Optional[Path] = None
    content_hash: str = ""


def _merge(a: Dict[str, Any], b: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(a)
    for k, v in (b or {}).items():
        out[k] = _merge(out[k], v) if isinstance(v, dict) and isinstance(out.get(k), dict) else v
    return out


def parse_file_rules(raw: Dict[str, Any], rules: Rules, source: str = "<file_rules>") -> FileRules:
    unknown = set(raw) - {"defaults", "files"}
    if unknown:
        raise FileRuleError("%s: unknown top-level key(s) %s (expected defaults, files)" % (source, sorted(unknown)))
    defaults = _merge(DEFAULTS, raw.get("defaults") or {})
    bad = set(defaults) - set(DEFAULTS)
    if bad:
        raise FileRuleError("%s: unknown defaults key(s) %s" % (source, sorted(bad)))
    out: List[FileRule] = []
    names = set()
    for i, f in enumerate(raw.get("files") or []):
        where = "%s files[%d]" % (source, i)
        if not isinstance(f, dict) or not f.get("pattern"):
            raise FileRuleError("%s: each file entry needs a 'pattern' (e.g. customers*.csv)" % where)
        allowed = {"name", "pattern", "format", "sheets", "columns"} | set(DEFAULTS)
        extra = set(f) - allowed
        if extra:
            raise FileRuleError("%s: unknown key(s) %s. Allowed: %s" % (where, sorted(extra), sorted(allowed)))
        name = str(f.get("name") or f["pattern"])
        if name in names:
            raise FileRuleError("%s: duplicate file entry name '%s'" % (where, name))
        names.add(name)
        opts = _merge(defaults, {k: f[k] for k in DEFAULTS if k in f})
        fmt = str(f.get("format") or "").lower()
        if fmt not in ("", "csv", "excel"):
            raise FileRuleError("%s: format must be csv or excel" % where)
        if opts["on_missing_column"] not in ("error", "warn"):
            raise FileRuleError("%s: on_missing_column must be error or warn" % where)
        if opts["on_value_error"] not in ("fail", "blank", "keep"):
            raise FileRuleError("%s: on_value_error must be fail, blank or keep" % where)
        if opts["excel"].get("mode") not in ("in_place", "streaming"):
            raise FileRuleError("%s: excel.mode must be in_place or streaming" % where)
        if not isinstance(opts["excel"].get("header_row"), int) or opts["excel"]["header_row"] < 1:
            raise FileRuleError("%s: excel.header_row must be a positive integer" % where)
        if not isinstance(opts["max_file_mb"], int) or opts["max_file_mb"] < 1:
            raise FileRuleError("%s: max_file_mb must be a positive integer" % where)
        if not isinstance(opts["csv"].get("max_field_kb"), int) or opts["csv"]["max_field_kb"] < 1:
            raise FileRuleError("%s: csv.max_field_kb must be a positive integer" % where)
        if len(str(opts["csv"].get("delimiter", ","))) != 1:
            raise FileRuleError("%s: csv.delimiter must be one character (use '\\t' for tab)" % where)
        cols: List[FileColumn] = []
        seen = set()
        for j, c in enumerate(f.get("columns") or []):
            cw = "%s.columns[%d]" % (where, j)
            if not isinstance(c, dict) or not c.get("name") or not c.get("domain"):
                raise FileRuleError("%s: each column needs 'name' (header text) and 'domain'" % cw)
            if str(c["name"]).strip().lower() in seen:
                raise FileRuleError("%s: column '%s' listed twice" % (cw, c["name"]))
            seen.add(str(c["name"]).strip().lower())
            dom = rules.domains.get(str(c["domain"]))
            if dom is None:
                raise FileRuleError("%s: domain '%s' is not defined in %s. File columns use the SAME domains as the "
                                    "database so values mask identically." % (cw, c["domain"], rules.source_path))
            cls = get_masker_class(dom.type)
            overrides = {k: v for k, v in c.items() if k not in ("name", "domain", "entity_column")}
            bad = set(overrides) - set(cls.column_overridable())
            if bad:
                raise FileRuleError("%s: unknown key(s) %s (format overrides allowed for %s: %s)"
                                    % (cw, sorted(bad), dom.type, sorted(cls.column_overridable()) or "none"))
            needs_entity = cls.entity_required(dom.params)
            if needs_entity and not c.get("entity_column"):
                raise FileRuleError("%s: domain '%s' shifts dates per person; add entity_column (the person id "
                                    "column in this file)" % (cw, dom.name))
            cols.append(FileColumn(str(c["name"]).strip(), dom.name, str(c.get("entity_column") or "").strip(),
                                   overrides))
        if not cols:
            raise FileRuleError("%s: no columns configured" % where)
        out.append(FileRule(name, str(f["pattern"]), cols, fmt, [str(s) for s in (f.get("sheets") or [])],
                            str(opts["output_suffix"]), opts["max_file_mb"], opts["on_missing_column"],
                            opts["on_value_error"], dict(opts["csv"]), dict(opts["excel"])))
    blob = json.dumps(raw, sort_keys=True, default=str).encode("utf-8")
    return FileRules(out, content_hash=hashlib.sha256(blob).hexdigest()[:16])


def load_file_rules(path: str, rules: Rules) -> FileRules:
    p = Path(path)
    if not p.exists():
        raise FileRuleError("File rules not found: %s. Create one with: python main.py files-discover" % p)
    fr = parse_file_rules(_read_yaml(p), rules, str(p))
    fr.source_path = p
    if not fr.files:
        raise FileRuleError("%s defines no files" % p)
    return fr


def file_format(path: Path, rule: Optional[FileRule] = None) -> str:
    if rule is not None and rule.format:
        return rule.format
    ext = path.suffix.lower()
    if ext in CSV_EXT:
        return "csv"
    if ext in EXCEL_EXT:
        return "excel"
    if ext == ".xls":
        raise FileRuleError("%s: old .xls format is not supported; save it as .xlsx" % path.name)
    raise FileRuleError("%s: unsupported file type %s (csv, txt, tsv, xlsx, xlsm)" % (path.name, ext))


def find_inputs(input_path: str, file_rules: FileRules) -> Tuple[List[Tuple[Path, FileRule]], List[Path]]:
    """Returns ([(file, rule)], [files with no matching rule])."""
    root = Path(input_path)
    if root.is_file():
        candidates, base = [root], root.parent
    elif root.is_dir():
        candidates = sorted(p for p in root.rglob("*") if p.is_file() and not p.name.startswith(("~$", ".")))
        base = root
    else:
        raise FileRuleError("Input path not found: %s (set file_input_dir in paths.yaml or pass --input)" % root)
    matched, unmatched = [], []
    for p in candidates:
        rel = str(p.relative_to(base))
        rule = next((r for r in file_rules.files if r.matches(rel)), None)
        (matched if rule else unmatched).append((p, rule) if rule else p)
    return matched, unmatched


def output_path_for(src: Path, input_root: Path, output_dir: Path, rule: FileRule) -> Path:
    base = input_root if input_root.is_dir() else input_root.parent
    rel = src.relative_to(base)
    return output_dir / rel.parent / ("%s%s%s" % (src.stem, rule.output_suffix, src.suffix))
