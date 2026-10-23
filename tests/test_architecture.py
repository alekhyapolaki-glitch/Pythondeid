"""Guards the package structure: each layer may only import from the layers below it."""

import ast
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1] / "deid"

# package -> packages it may import from (besides itself)
ALLOWED = {
    "utils": set(),
    "masking": set(),
    "config": {"masking"},
    "database": {"masking", "config", "utils"},
    "audit": {"database"},
    "advisor": {"masking", "database"},
    "engine": {"masking", "config", "database", "audit", "advisor"},
    "files": {"masking", "config", "engine"},
    "cli": {"masking", "config", "database", "audit", "advisor", "engine", "files", "utils"},
}
MAX_MODULE_LINES = 650


def _modules():
    for p in ROOT.rglob("*.py"):
        yield p, p.relative_to(ROOT).with_suffix("").parts


def test_no_upward_or_sideways_imports():
    bad = []
    for path, parts in _modules():
        pkg = parts[0]
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.ImportFrom) and node.level:
                target = list(parts[:-1])[: len(parts) - node.level] + (node.module.split(".") if node.module else [])
                if target and target[0] != pkg and target[0] not in ALLOWED.get(pkg, set()):
                    bad.append("%s imports %s" % (path.relative_to(ROOT), ".".join(target)))
    assert not bad, bad


def test_every_module_is_documented_and_reasonably_sized():
    for path, _ in _modules():
        src = path.read_text(encoding="utf-8")
        assert ast.get_docstring(ast.parse(src)), "%s has no module docstring" % path
        assert src.count("\n") <= MAX_MODULE_LINES, "%s is too large; split it by responsibility" % path


def test_entry_point_is_thin():
    main = (ROOT.parent / "main.py").read_text(encoding="utf-8")
    assert main.count("\n") < 20 and "from deid.cli import main" in main
