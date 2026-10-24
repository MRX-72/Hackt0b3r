"""Writes docs/TRACE.md (requirement -> tests); fails if tests cite unknown requirement IDs."""

import csv
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ID = re.compile(r"R-[A-Z]+-\d+")


def main() -> int:
    reqs = list(csv.DictReader((ROOT / "docs/REQUIREMENTS.csv").open()))
    known = {r["id"] for r in reqs}
    refs: dict[str, list[str]] = {}
    for test in sorted((ROOT / "tests").rglob("test_*.py")):
        for rid in set(ID.findall(test.read_text())):
            refs.setdefault(rid, []).append(test.name)
    unknown = sorted(set(refs) - known)
    lines = ["# TRACE", "", "| requirement | priority | component | tests |", "|---|---|---|---|"]
    for r in reqs:
        tests = ", ".join(refs.get(r["id"], [])) or "NONE"
        lines.append(f"| {r['id']} | {r['priority']} | {r['component']} | {tests} |")
    (ROOT / "docs/TRACE.md").write_text("\n".join(lines) + "\n")
    if unknown:
        print(f"tests reference unknown requirement IDs: {unknown}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
