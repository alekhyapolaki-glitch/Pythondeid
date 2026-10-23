"""Small, dependency-free console question helpers."""

from __future__ import annotations

from typing import List, Optional, Sequence


def ask(question: str, default: Optional[str] = None, required: bool = True) -> str:
    suffix = " [%s]" % default if default not in (None, "") else ""
    while True:
        answer = input("%s%s: " % (question, suffix)).strip()
        if not answer and default is not None:
            return default
        if answer or not required:
            return answer
        print("  A value is required.")


def ask_yes_no(question: str, default: bool = False) -> bool:
    hint = "Y/n" if default else "y/N"
    while True:
        answer = input("%s [%s]: " % (question, hint)).strip().lower()
        if not answer:
            return default
        if answer in ("y", "yes"):
            return True
        if answer in ("n", "no"):
            return False
        print("  Please answer y or n.")


def ask_int(question: str, default: int, minimum: int = 0) -> int:
    while True:
        raw = ask(question, str(default))
        try:
            value = int(raw)
            if value >= minimum:
                return value
        except ValueError:
            pass
        print("  Please enter a whole number >= %d." % minimum)


def choose(question: str, options: Sequence[str], default: Optional[str] = None) -> str:
    for i, opt in enumerate(options, start=1):
        print("   %2d) %s" % (i, opt))
    while True:
        raw = ask(question, default)
        if raw in options:
            return raw
        if raw.isdigit() and 1 <= int(raw) <= len(options):
            return options[int(raw) - 1]
        print("  Pick a number from the list or type the option exactly.")


def choose_many(question: str, options: Sequence[str], default: str = "all") -> List[str]:
    """Accepts 'all', 'none', or comma separated numbers / ranges like 1,3,5-8."""
    for i, opt in enumerate(options, start=1):
        print("   %3d) %s" % (i, opt))
    while True:
        raw = ask(question + " (e.g. 1,3,5-8 | all | none)", default).lower()
        if raw == "all":
            return list(options)
        if raw == "none":
            return []
        picked: List[str] = []
        try:
            for part in raw.split(","):
                part = part.strip()
                if "-" in part:
                    a, b = part.split("-", 1)
                    picked.extend(options[i - 1] for i in range(int(a), int(b) + 1))
                elif part:
                    picked.append(options[int(part) - 1])
            return list(dict.fromkeys(picked))
        except (ValueError, IndexError):
            print("  Invalid selection.")


def confirm_phrase(question: str, phrase: str) -> bool:
    answer = input("%s\n  Type '%s' to continue: " % (question, phrase)).strip()
    return answer == phrase
