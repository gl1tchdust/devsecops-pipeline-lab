#!/usr/bin/env python3
"""Release gate for the security toolchain.

Reads every report the pipeline produced, normalises them into one finding
shape, applies the suppression list, and fails the build when anything
High or Critical survives.

Two things make a build fail:

  1. An unsuppressed High or Critical finding from any tool.
  2. An expired suppression. Suppressions rot: a dated exception nobody
     revisits is a permanent hole with extra steps. Letting the gate go green
     on one would defeat the point of writing the expiry down.

Everything Medium and below is printed and ignored. That split is deliberate
and is argued for in the README.

Usage:
    python gate/gate.py --reports reports/ --suppressions gate/suppressions.yml
"""

from __future__ import annotations

import argparse
import dataclasses
import datetime as dt
import json
import pathlib
import sys

import yaml

BLOCKING = {"CRITICAL", "HIGH"}

# SARIF carries a numeric security-severity (CVSS-style) when the tool bothers
# to set one, and a coarse level when it does not. Prefer the number.
_LEVEL_FALLBACK = {"error": "HIGH", "warning": "MEDIUM", "note": "LOW", "none": "LOW"}

# ZAP speaks riskcode, not SARIF.
_ZAP_RISK = {"0": "LOW", "1": "LOW", "2": "MEDIUM", "3": "HIGH"}


@dataclasses.dataclass(frozen=True)
class Finding:
    tool: str
    rule_id: str
    severity: str
    location: str
    message: str


def _severity_from_sarif(result: dict, rule: dict) -> str:
    props = {**rule.get("properties", {}), **result.get("properties", {})}
    raw = props.get("security-severity")
    if raw is not None:
        try:
            score = float(raw)
        except (TypeError, ValueError):
            score = None
        if score is not None:
            if score >= 9.0:
                return "CRITICAL"
            if score >= 7.0:
                return "HIGH"
            if score >= 4.0:
                return "MEDIUM"
            return "LOW"

    # SARIF 2.1.0 §3.27.10: a result omits `level` when it matches the level
    # the rule already declares, so the rule's defaultConfiguration has to be
    # consulted before falling back to the spec default of "warning".
    #
    # Semgrep relies on this. It writes no `level` on results and no
    # `security-severity` at all, putting everything in
    # defaultConfiguration.level. Reading only `result.level` silently graded
    # every Semgrep finding, including a hardcoded Flask SECRET_KEY, as MEDIUM
    # and let it through the gate.
    level = (
        result.get("level")
        or rule.get("defaultConfiguration", {}).get("level")
        or "warning"
    )
    return _LEVEL_FALLBACK.get(level, "MEDIUM")


def _location_from_sarif(result: dict) -> str:
    for loc in result.get("locations", []):
        phys = loc.get("physicalLocation", {})
        uri = phys.get("artifactLocation", {}).get("uri", "")
        line = phys.get("region", {}).get("startLine")
        if uri:
            return f"{uri}:{line}" if line else uri
    return "-"


def _first_line(text: str | None) -> str:
    if not text:
        return ""
    stripped = text.strip()
    if not stripped:
        return ""
    return stripped.splitlines()[0][:120]


def parse_sarif(path: pathlib.Path, tool_hint: str) -> list[Finding]:
    doc = json.loads(path.read_text(encoding="utf-8"))
    findings: list[Finding] = []
    for run in doc.get("runs", []):
        driver = run.get("tool", {}).get("driver", {})
        tool = driver.get("name") or tool_hint
        rules = {r.get("id"): r for r in driver.get("rules", []) if r.get("id")}
        for result in run.get("results", []):
            rule_id = result.get("ruleId") or "-"
            findings.append(
                Finding(
                    tool=tool,
                    rule_id=rule_id,
                    severity=_severity_from_sarif(result, rules.get(rule_id, {})),
                    location=_location_from_sarif(result),
                    message=_first_line(result.get("message", {}).get("text")),
                )
            )
    return findings


def parse_zap(path: pathlib.Path) -> list[Finding]:
    """ZAP's JSON report. Not SARIF, so it gets its own adapter."""
    doc = json.loads(path.read_text(encoding="utf-8"))
    findings: list[Finding] = []
    for site in doc.get("site", []):
        target = site.get("@name", "-")
        for alert in site.get("alerts", []):
            findings.append(
                Finding(
                    tool="zap",
                    rule_id=str(alert.get("pluginid", "-")),
                    severity=_ZAP_RISK.get(str(alert.get("riskcode", "0")), "LOW"),
                    location=target,
                    message=_first_line(alert.get("alert")),
                )
            )
    return findings


def collect(reports_dir: pathlib.Path) -> list[Finding]:
    """Read every report in the directory.

    Tools disagree about whether SARIF belongs in a .json or a .sarif file, so
    accept both rather than silently skipping half the evidence.
    """
    findings: list[Finding] = []
    paths = sorted({*reports_dir.rglob("*.json"), *reports_dir.rglob("*.sarif")})
    for path in paths:
        stem = path.stem.lower()
        try:
            if "zap" in stem:
                findings.extend(parse_zap(path))
            else:
                findings.extend(parse_sarif(path, tool_hint=stem))
        except (json.JSONDecodeError, AttributeError, TypeError) as exc:
            # A malformed report is a broken pipeline, not a clean run. Never
            # let an unparseable file be mistaken for "no findings".
            print(f"::error::cannot parse {path.name}: {exc}", file=sys.stderr)
            raise SystemExit(2) from exc
    return findings


def load_suppressions(path: pathlib.Path) -> list[dict]:
    if not path.exists():
        return []
    doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return doc.get("suppressions") or []


def check_suppressions(suppressions: list[dict], today: dt.date) -> list[str]:
    """Problems with the suppression file itself. Any of these fails the gate."""
    problems = []
    for entry in suppressions:
        rule_id = entry.get("id", "<missing id>")
        if not entry.get("reason"):
            problems.append(f"suppression {rule_id!r} has no justification")
        expires = entry.get("expires")
        if not expires:
            problems.append(f"suppression {rule_id!r} has no expiry date")
            continue
        if isinstance(expires, str):
            try:
                expires = dt.date.fromisoformat(expires)
            except ValueError:
                problems.append(f"suppression {rule_id!r} has an unparseable expiry {expires!r}")
                continue
        if isinstance(expires, dt.datetime):
            expires = expires.date()
        if expires < today:
            problems.append(f"suppression {rule_id!r} expired on {expires.isoformat()}")
    return problems


def is_suppressed(finding: Finding, suppressions: list[dict]) -> bool:
    for entry in suppressions:
        if entry.get("id") != finding.rule_id:
            continue
        tool = entry.get("tool")
        if tool and tool.lower() not in finding.tool.lower():
            continue
        path = entry.get("path")
        if path and path not in finding.location:
            continue
        return True
    return False


def main() -> int:
    ap = argparse.ArgumentParser(description="Fail the build on High/Critical findings.")
    ap.add_argument("--reports", type=pathlib.Path, required=True)
    ap.add_argument("--suppressions", type=pathlib.Path, required=True)
    ap.add_argument("--today", type=dt.date.fromisoformat, default=dt.date.today())
    args = ap.parse_args()

    if not args.reports.exists():
        print(f"::error::reports directory {args.reports} does not exist", file=sys.stderr)
        return 2

    suppressions = load_suppressions(args.suppressions)
    findings = collect(args.reports)

    hygiene = check_suppressions(suppressions, args.today)
    for problem in hygiene:
        print(f"::error::{problem}")

    blocking, suppressed, logged = [], [], []
    for f in findings:
        if f.severity not in BLOCKING:
            logged.append(f)
        elif is_suppressed(f, suppressions):
            suppressed.append(f)
        else:
            blocking.append(f)

    print(
        f"\nfindings: {len(findings)}  blocking: {len(blocking)}  "
        f"suppressed: {len(suppressed)}  logged: {len(logged)}\n"
    )

    for label, group in (("BLOCKING", blocking), ("SUPPRESSED", suppressed), ("LOGGED", logged)):
        if not group:
            continue
        print(f"--- {label} ---")
        for f in sorted(group, key=lambda x: (x.tool, x.rule_id)):
            print(f"  {f.severity:<8} {f.tool:<14} {f.rule_id:<44} {f.location}")
        print()

    if blocking:
        print(f"::error::gate failed: {len(blocking)} unsuppressed High/Critical finding(s)")
    if hygiene:
        print(f"::error::gate failed: {len(hygiene)} problem(s) in {args.suppressions}")

    return 1 if (blocking or hygiene) else 0


if __name__ == "__main__":
    raise SystemExit(main())
