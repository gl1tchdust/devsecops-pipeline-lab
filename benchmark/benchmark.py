#!/usr/bin/env python3
"""Score the custom rules against hand-labelled ground truth.

Precision and recall for a Semgrep ruleset, computed from a checked-in label
file so the numbers in the README can be re-derived and disputed.

    python benchmark/benchmark.py --target target/vampi \
                                  --labels benchmark/labels/vampi.yml \
                                  --rules semgrep/rules/python

With `--min-precision` / `--min-recall` it doubles as a regression test: edit a
rule, lose recall, fail the build. CI passes the measured values as the floor.

Exit codes:
    0  scored, and any thresholds given were met
    1  a threshold was not met
    2  could not run the scan or read the labels
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import pathlib
import subprocess
import sys

import yaml


@dataclasses.dataclass(frozen=True)
class Finding:
    file: str
    line: int
    rule: str


@dataclasses.dataclass(frozen=True)
class Label:
    file: str
    line: int
    bug_class: str
    endpoint: str
    note: str


@dataclasses.dataclass
class Score:
    matched: list[tuple[Label, Finding]]
    missed: list[Label]
    spurious: list[Finding]

    @property
    def tp(self) -> int:
        return len(self.matched)

    @property
    def fn(self) -> int:
        return len(self.missed)

    @property
    def fp(self) -> int:
        return len(self.spurious)

    @property
    def precision(self) -> float:
        denom = self.tp + self.fp
        return self.tp / denom if denom else 0.0

    @property
    def recall(self) -> float:
        denom = self.tp + self.fn
        return self.tp / denom if denom else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    def by_rule(self) -> dict[str, dict[str, float | int]]:
        """Per-rule true/false positive counts.

        Aggregate precision hides which rule is carrying the noise, and that
        is the number that decides whether a rule is allowed to block a
        release. Recall is deliberately absent: a label records a defect, not
        which rule ought to have found it, so attributing a miss to one rule
        would be an assumption rather than a measurement.
        """
        stats: dict[str, dict[str, float | int]] = {}
        for _, finding in self.matched:
            stats.setdefault(finding.rule, {"tp": 0, "fp": 0})["tp"] += 1
        for finding in self.spurious:
            stats.setdefault(finding.rule, {"tp": 0, "fp": 0})["fp"] += 1
        for row in stats.values():
            total = row["tp"] + row["fp"]
            row["precision"] = round(row["tp"] / total, 4) if total else 0.0
        return stats


def _norm(path: str) -> str:
    return path.replace("\\", "/").strip("/")


def score(findings: list[Finding], labels: list[Label], tolerance: int = 0) -> Score:
    """Match findings against labels.

    One finding may satisfy at most one label and vice versa: a rule that fires
    three times on one defect should not be credited with three true positives.
    Labels are consumed in file/line order so the pairing is deterministic.
    """
    remaining = list(findings)
    matched: list[tuple[Label, Finding]] = []
    missed: list[Label] = []

    for label in sorted(labels, key=lambda l: (l.file, l.line)):
        hit = None
        for finding in remaining:
            if finding.file == label.file and abs(finding.line - label.line) <= tolerance:
                hit = finding
                break
        if hit is None:
            missed.append(label)
        else:
            remaining.remove(hit)
            matched.append((label, hit))

    return Score(matched=matched, missed=missed, spurious=remaining)


def load_labels(path: pathlib.Path) -> tuple[dict, list[Label]]:
    doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    target = doc.get("target") or {}
    labels = [
        Label(
            file=_norm(d["file"]),
            line=int(d["line"]),
            bug_class=d.get("class", "-"),
            endpoint=d.get("endpoint", "-"),
            note=" ".join((d.get("note") or "").split()),
        )
        for d in (doc.get("defects") or [])
    ]
    return target, labels


def run_semgrep(rules: pathlib.Path, target: pathlib.Path, scope: list[str]) -> list[Finding]:
    paths = [str(target / s) for s in scope] if scope else [str(target)]
    existing = [p for p in paths if pathlib.Path(p).exists()]
    if not existing:
        print(f"::error::none of the scoped paths exist under {target}", file=sys.stderr)
        raise SystemExit(2)

    cmd = ["semgrep", "--config", str(rules), "--metrics", "off", "--quiet", "--json", *existing]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if not proc.stdout.strip():
        print(f"::error::semgrep produced no output\n{proc.stderr[-2000:]}", file=sys.stderr)
        raise SystemExit(2)

    doc = json.loads(proc.stdout)
    for err in doc.get("errors", []):
        print(f"::warning::semgrep: {err.get('message', err)}", file=sys.stderr)

    findings = []
    for r in doc.get("results", []):
        rel = _norm(str(pathlib.Path(r["path"]).resolve().relative_to(target.resolve())))
        findings.append(
            Finding(file=rel, line=int(r["start"]["line"]), rule=r["check_id"].split(".")[-1])
        )
    return findings


def report(target_meta: dict, result: Score) -> str:
    out = []
    out.append(f"target      {target_meta.get('name', '?')} @ {str(target_meta.get('commit', '?'))[:8]}")
    out.append(f"language    {target_meta.get('language', '?')} / {target_meta.get('framework', '?')}")
    out.append("")
    out.append(f"labelled defects   {result.tp + result.fn}")
    out.append(f"true positives     {result.tp}")
    out.append(f"false negatives    {result.fn}")
    out.append(f"false positives    {result.fp}")
    out.append("")
    out.append(f"precision   {result.precision:.3f}")
    out.append(f"recall      {result.recall:.3f}")
    out.append(f"f1          {result.f1:.3f}")

    if result.matched:
        out.append("\n--- caught ---")
        for label, finding in sorted(result.matched, key=lambda m: (m[0].file, m[0].line)):
            out.append(f"  {label.file}:{label.line:<5} {label.bug_class:<16} {finding.rule}")

    if result.missed:
        out.append("\n--- missed (false negatives) ---")
        for label in result.missed:
            out.append(f"  {label.file}:{label.line:<5} {label.bug_class:<16} {label.endpoint}")
            out.append(f"      {label.note[:150]}")

    per_rule = result.by_rule()
    if per_rule:
        out.append("\n--- per rule ---")
        out.append(f"  {'rule':<44} {'TP':>3} {'FP':>3}  precision")
        for name, row in sorted(per_rule.items(), key=lambda kv: -kv[1]["tp"]):
            out.append(f"  {name:<44} {row['tp']:>3} {row['fp']:>3}  {row['precision']:.3f}")

    if result.spurious:
        out.append("\n--- unlabelled findings (false positives) ---")
        for finding in sorted(result.spurious, key=lambda f: (f.file, f.line)):
            out.append(f"  {finding.file}:{finding.line:<5} {finding.rule}")

    return "\n".join(out)


def main() -> int:
    ap = argparse.ArgumentParser(description="Score rules against labelled ground truth.")
    ap.add_argument("--target", type=pathlib.Path, required=True)
    ap.add_argument("--labels", type=pathlib.Path, required=True)
    ap.add_argument("--rules", type=pathlib.Path, required=True)
    ap.add_argument("--tolerance", type=int, default=0,
                    help="allowed line drift when matching a finding to a label")
    ap.add_argument("--min-precision", type=float, default=None)
    ap.add_argument("--min-recall", type=float, default=None)
    ap.add_argument("--json-out", type=pathlib.Path, default=None)
    args = ap.parse_args()

    if not args.labels.exists():
        print(f"::error::labels file not found: {args.labels}", file=sys.stderr)
        return 2
    if not args.target.exists():
        print(f"::error::target not found: {args.target}. Run target/fetch.sh first.", file=sys.stderr)
        return 2

    target_meta, labels = load_labels(args.labels)
    if not labels:
        print(f"::error::{args.labels} contains no defects", file=sys.stderr)
        return 2

    findings = run_semgrep(args.rules, args.target, target_meta.get("scope") or [])
    result = score(findings, labels, tolerance=args.tolerance)

    print(report(target_meta, result))

    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(
            json.dumps(
                {
                    "target": target_meta.get("name"),
                    "commit": target_meta.get("commit"),
                    "labelled": result.tp + result.fn,
                    "tp": result.tp,
                    "fp": result.fp,
                    "fn": result.fn,
                    "precision": round(result.precision, 4),
                    "recall": round(result.recall, 4),
                    "f1": round(result.f1, 4),
                    "by_rule": result.by_rule(),
                },
                indent=2,
            ),
            encoding="utf-8",
        )

    failed = False
    if args.min_precision is not None and result.precision < args.min_precision:
        print(f"\n::error::precision {result.precision:.3f} below floor {args.min_precision:.3f}")
        failed = True
    if args.min_recall is not None and result.recall < args.min_recall:
        print(f"\n::error::recall {result.recall:.3f} below floor {args.min_recall:.3f}")
        failed = True

    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
