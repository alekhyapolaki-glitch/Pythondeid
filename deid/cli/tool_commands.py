"""Utility commands: preview, list-types, test-vectors."""

from __future__ import annotations

import csv
import json

from ..config import (
    load_rules,
)
from ..masking import ALGORITHM_VERSION, MASKERS, MaskerError, build_maskers, create_masker
from .common import _keyring, _load


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
