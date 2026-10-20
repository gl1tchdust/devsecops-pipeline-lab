"""Tests for the release gate.

The gate is the only thing standing between a High finding and a green build,
so every branch that can wave a build through gets a test.
"""

from __future__ import annotations

import datetime as dt
import json
import sys

import pytest

import gate


def write_sarif(path, *, rule_id="X", security_severity=None, level="warning", uri="a.py", line=1):
    rule = {"id": rule_id}
    if security_severity is not None:
        rule["properties"] = {"security-severity": security_severity}
    doc = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "testtool", "rules": [rule]}},
                "results": [
                    {
                        "ruleId": rule_id,
                        "level": level,
                        "message": {"text": "something"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": uri},
                                    "region": {"startLine": line},
                                }
                            }
                        ],
                    }
                ],
            }
        ],
    }
    path.write_text(json.dumps(doc), encoding="utf-8")
    return path


def write_suppressions(path, entries):
    lines = ["suppressions:"]
    for e in entries:
        lines.append(f"  - id: {e['id']}")
        for key in ("tool", "path", "reason", "expires"):
            if key in e:
                lines.append(f"    {key}: {e[key]}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def run_gate(monkeypatch, reports_dir, suppressions_path, today="2026-01-01"):
    argv = [
        "gate.py",
        "--reports", str(reports_dir),
        "--suppressions", str(suppressions_path),
        "--today", today,
    ]
    monkeypatch.setattr(sys, "argv", argv)
    return gate.main()


# --- severity normalisation --------------------------------------------------


@pytest.mark.parametrize(
    "score,expected",
    [("9.8", "CRITICAL"), ("9.0", "CRITICAL"), ("7.5", "HIGH"), ("7.0", "HIGH"),
     ("6.9", "MEDIUM"), ("4.0", "MEDIUM"), ("3.9", "LOW"), ("0.0", "LOW")],
)
def test_cvss_score_maps_to_band(score, expected):
    rule = {"properties": {"security-severity": score}}
    assert gate._severity_from_sarif({}, rule) == expected


def test_falls_back_to_level_when_no_score():
    assert gate._severity_from_sarif({"level": "error"}, {}) == "HIGH"
    assert gate._severity_from_sarif({"level": "note"}, {}) == "LOW"


def test_unparseable_score_falls_back_rather_than_crashing():
    rule = {"properties": {"security-severity": "not-a-number"}}
    assert gate._severity_from_sarif({"level": "error"}, rule) == "HIGH"


# --- what blocks and what does not -------------------------------------------


def test_high_finding_fails_the_build(tmp_path, monkeypatch):
    reports = tmp_path / "reports"
    reports.mkdir()
    write_sarif(reports / "semgrep.json", rule_id="bola", security_severity="8.5")
    sup = write_suppressions(tmp_path / "s.yml", [])
    assert run_gate(monkeypatch, reports, sup) == 1


def test_medium_finding_is_logged_not_blocked(tmp_path, monkeypatch):
    reports = tmp_path / "reports"
    reports.mkdir()
    write_sarif(reports / "semgrep.json", rule_id="nit", security_severity="5.0")
    sup = write_suppressions(tmp_path / "s.yml", [])
    assert run_gate(monkeypatch, reports, sup) == 0


def test_live_suppression_silences_a_high(tmp_path, monkeypatch):
    reports = tmp_path / "reports"
    reports.mkdir()
    write_sarif(reports / "trivy.json", rule_id="CVE-2026-0001", security_severity="9.1")
    sup = write_suppressions(
        tmp_path / "s.yml",
        [{"id": "CVE-2026-0001", "reason": "not reachable", "expires": "2026-06-01"}],
    )
    assert run_gate(monkeypatch, reports, sup, today="2026-01-01") == 0


def test_expired_suppression_fails_the_build(tmp_path, monkeypatch):
    """The whole point of an expiry date is that the gate enforces it."""
    reports = tmp_path / "reports"
    reports.mkdir()
    write_sarif(reports / "trivy.json", rule_id="CVE-2026-0001", security_severity="9.1")
    sup = write_suppressions(
        tmp_path / "s.yml",
        [{"id": "CVE-2026-0001", "reason": "not reachable", "expires": "2025-06-01"}],
    )
    assert run_gate(monkeypatch, reports, sup, today="2026-01-01") == 1


def test_suppression_without_justification_fails(tmp_path, monkeypatch):
    reports = tmp_path / "reports"
    reports.mkdir()
    sup = write_suppressions(tmp_path / "s.yml", [{"id": "X", "expires": "2026-06-01"}])
    assert run_gate(monkeypatch, reports, sup) == 1


def test_suppression_without_expiry_fails(tmp_path, monkeypatch):
    reports = tmp_path / "reports"
    reports.mkdir()
    sup = write_suppressions(tmp_path / "s.yml", [{"id": "X", "reason": "because"}])
    assert run_gate(monkeypatch, reports, sup) == 1


def test_suppression_is_scoped_to_its_tool(tmp_path, monkeypatch):
    """A suppression written for Trivy must not silence Semgrep's finding."""
    reports = tmp_path / "reports"
    reports.mkdir()
    write_sarif(reports / "semgrep.json", rule_id="shared-id", security_severity="8.0")
    sup = write_suppressions(
        tmp_path / "s.yml",
        [{"id": "shared-id", "tool": "trivy", "reason": "other tool", "expires": "2026-06-01"}],
    )
    assert run_gate(monkeypatch, reports, sup) == 1


def test_suppression_is_scoped_to_its_path(tmp_path, monkeypatch):
    reports = tmp_path / "reports"
    reports.mkdir()
    write_sarif(reports / "semgrep.json", rule_id="r1", security_severity="8.0", uri="src/live.py")
    sup = write_suppressions(
        tmp_path / "s.yml",
        [{"id": "r1", "path": "tests/", "reason": "fixture only", "expires": "2026-06-01"}],
    )
    assert run_gate(monkeypatch, reports, sup) == 1


# --- ZAP adapter -------------------------------------------------------------


def test_zap_high_risk_blocks(tmp_path, monkeypatch):
    reports = tmp_path / "reports"
    reports.mkdir()
    doc = {
        "site": [
            {
                "@name": "http://localhost:5000",
                "alerts": [{"pluginid": "40012", "riskcode": "3", "alert": "XSS"}],
            }
        ]
    }
    (reports / "zap.json").write_text(json.dumps(doc), encoding="utf-8")
    sup = write_suppressions(tmp_path / "s.yml", [])
    assert run_gate(monkeypatch, reports, sup) == 1


def test_zap_informational_does_not_block(tmp_path, monkeypatch):
    reports = tmp_path / "reports"
    reports.mkdir()
    doc = {
        "site": [
            {
                "@name": "http://localhost:5000",
                "alerts": [{"pluginid": "10015", "riskcode": "0", "alert": "Cache-control"}],
            }
        ]
    }
    (reports / "zap.json").write_text(json.dumps(doc), encoding="utf-8")
    sup = write_suppressions(tmp_path / "s.yml", [])
    assert run_gate(monkeypatch, reports, sup) == 0


# --- failure modes that must never look like a clean run ---------------------


def test_malformed_report_aborts_instead_of_passing(tmp_path, monkeypatch):
    """A truncated report must not be read as 'no findings'."""
    reports = tmp_path / "reports"
    reports.mkdir()
    (reports / "trivy.json").write_text("{ this is not json", encoding="utf-8")
    sup = write_suppressions(tmp_path / "s.yml", [])
    with pytest.raises(SystemExit) as exc:
        run_gate(monkeypatch, reports, sup)
    assert exc.value.code == 2


def test_missing_reports_directory_is_an_error(tmp_path, monkeypatch):
    sup = write_suppressions(tmp_path / "s.yml", [])
    assert run_gate(monkeypatch, tmp_path / "nope", sup) == 2


def test_empty_run_is_green(tmp_path, monkeypatch):
    reports = tmp_path / "reports"
    reports.mkdir()
    sup = write_suppressions(tmp_path / "s.yml", [])
    assert run_gate(monkeypatch, reports, sup) == 0


def test_expiry_boundary_is_inclusive(tmp_path, monkeypatch):
    """A suppression is still valid on its expiry date, dead the day after."""
    reports = tmp_path / "reports"
    reports.mkdir()
    write_sarif(reports / "trivy.json", rule_id="CVE-1", security_severity="9.5")
    sup = write_suppressions(
        tmp_path / "s.yml", [{"id": "CVE-1", "reason": "r", "expires": "2026-01-01"}]
    )
    assert run_gate(monkeypatch, reports, sup, today="2026-01-01") == 0
    assert run_gate(monkeypatch, reports, sup, today="2026-01-02") == 1


def test_check_suppressions_accepts_native_yaml_dates():
    """PyYAML turns an unquoted ISO date into datetime.date, not str."""
    entries = [{"id": "X", "reason": "r", "expires": dt.date(2026, 6, 1)}]
    assert gate.check_suppressions(entries, dt.date(2026, 1, 1)) == []
    assert gate.check_suppressions(entries, dt.date(2026, 12, 1)) != []


# --- SARIF defaultConfiguration -------------------------------------------
#
# Regression tests for a real bug: the gate read only `result.level`, so every
# Semgrep finding graded as MEDIUM and never blocked. Semgrep omits
# `result.level` and `security-severity` entirely and puts the severity in
# `rule.defaultConfiguration.level`, which the SARIF spec says is where a
# consumer must look when the result has no level of its own.


def test_rule_default_configuration_supplies_the_level():
    rule = {"defaultConfiguration": {"level": "error"}}
    assert gate._severity_from_sarif({}, rule) == "HIGH"


def test_result_level_beats_rule_default():
    rule = {"defaultConfiguration": {"level": "error"}}
    assert gate._severity_from_sarif({"level": "note"}, rule) == "LOW"


def test_security_severity_beats_both():
    rule = {
        "defaultConfiguration": {"level": "note"},
        "properties": {"security-severity": "9.5"},
    }
    assert gate._severity_from_sarif({}, rule) == "CRITICAL"


def test_spec_default_still_applies_with_neither():
    assert gate._severity_from_sarif({}, {}) == "MEDIUM"


def test_semgrep_shaped_error_finding_blocks(tmp_path, monkeypatch):
    """End to end: a Semgrep-shaped report with no result level must block."""
    reports = tmp_path / "reports"
    reports.mkdir()
    doc = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Semgrep OSS",
                        "rules": [
                            {
                                "id": "hardcoded-secret",
                                "defaultConfiguration": {"level": "error"},
                                "properties": {"tags": ["security"]},
                            }
                        ],
                    }
                },
                "results": [
                    {
                        "ruleId": "hardcoded-secret",
                        "message": {"text": "hardcoded secret"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "config.py"},
                                    "region": {"startLine": 13},
                                }
                            }
                        ],
                    }
                ],
            }
        ],
    }
    (reports / "semgrep.sarif").write_text(json.dumps(doc), encoding="utf-8")
    sup = write_suppressions(tmp_path / "s.yml", [])
    assert run_gate(monkeypatch, reports, sup) == 1
