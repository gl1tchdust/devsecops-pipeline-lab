#!/usr/bin/env python3
"""Render benchmark JSON as a markdown table.

Used for the GitHub Actions job summary, which is the only place the accuracy
numbers are visible without digging through logs.

    python benchmark/summarise.py benchmark-results

Prints a note rather than failing when there is nothing to summarise: this runs
with `if: always()`, so an earlier failure must not be masked by this step
erroring too.
"""

from __future__ import annotations

import json
import pathlib
import sys

COLUMNS = ("target", "labelled", "tp", "fp", "fn", "precision", "recall", "f1")
HEADERS = ("target", "labelled", "TP", "FP", "FN", "precision", "recall", "f1")


def render(results: list[dict]) -> str:
    lines = ["## Rule accuracy", "", "| " + " | ".join(HEADERS) + " |",
             "|" + "---|" * len(HEADERS)]
    for d in results:
        lines.append("| " + " | ".join(str(d.get(c, "-")) for c in COLUMNS) + " |")
    lines.append("")
    lines.append("Scored against hand-labelled ground truth in `benchmark/labels/`.")
    return "\n".join(lines)


def main() -> int:
    directory = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "benchmark-results")
    if not directory.is_dir():
        print(f"_No benchmark results at `{directory}`._")
        return 0

    results = []
    for path in sorted(directory.glob("*.json")):
        try:
            results.append(json.loads(path.read_text(encoding="utf-8")))
        except (json.JSONDecodeError, OSError) as exc:
            print(f"_Could not read `{path.name}`: {exc}._")

    if not results:
        print(f"_No benchmark results in `{directory}`._")
        return 0

    print(render(results))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
