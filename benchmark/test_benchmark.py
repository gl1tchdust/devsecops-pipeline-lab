"""Tests for the benchmark scorer.

A scorer that overcounts true positives flatters the ruleset, which is the one
failure mode that makes the whole benchmark worthless. The pairing rules get
tested harder than anything else here.
"""

from __future__ import annotations

import pathlib

import pytest

from benchmark import Finding, Label, Score, load_labels, score


def L(file="a.py", line=10, bug_class="bola"):
    return Label(file=file, line=line, bug_class=bug_class, endpoint="-", note="")


def F(file="a.py", line=10, rule="r"):
    return Finding(file=file, line=line, rule=rule)


# --- pairing ----------------------------------------------------------------


def test_exact_match_is_a_true_positive():
    r = score([F(line=10)], [L(line=10)])
    assert (r.tp, r.fp, r.fn) == (1, 0, 0)


def test_wrong_line_is_both_a_miss_and_a_false_positive():
    """A finding on the wrong line has not found the defect."""
    r = score([F(line=99)], [L(line=10)])
    assert (r.tp, r.fp, r.fn) == (0, 1, 1)


def test_wrong_file_does_not_match():
    r = score([F(file="b.py", line=10)], [L(file="a.py", line=10)])
    assert (r.tp, r.fp, r.fn) == (0, 1, 1)


def test_tolerance_allows_line_drift():
    assert score([F(line=12)], [L(line=10)], tolerance=2).tp == 1
    assert score([F(line=13)], [L(line=10)], tolerance=2).tp == 0


def test_tolerance_is_symmetric():
    assert score([F(line=8)], [L(line=10)], tolerance=2).tp == 1


def test_two_findings_on_one_defect_count_once():
    """Firing twice on one line is not two bugs found."""
    r = score([F(line=10, rule="x"), F(line=10, rule="y")], [L(line=10)])
    assert (r.tp, r.fp, r.fn) == (1, 1, 0)


def test_one_finding_cannot_satisfy_two_labels():
    """Two distinct defects need two findings, even within tolerance."""
    r = score([F(line=10)], [L(line=10), L(line=11)], tolerance=5)
    assert (r.tp, r.fn) == (1, 1)


def test_each_label_consumes_a_distinct_finding():
    r = score([F(line=10), F(line=11)], [L(line=10), L(line=11)])
    assert (r.tp, r.fp, r.fn) == (2, 0, 0)


def test_pairing_is_deterministic_regardless_of_finding_order():
    labels = [L(line=10), L(line=20)]
    a = score([F(line=10), F(line=20)], labels)
    b = score([F(line=20), F(line=10)], labels)
    assert (a.tp, a.fp, a.fn) == (b.tp, b.fp, b.fn) == (2, 0, 0)


# --- metrics ----------------------------------------------------------------


def test_metrics_on_the_known_vampi_shape():
    """5 true, 2 missed, 1 spurious. The real measured result."""
    labels = [L(line=i) for i in range(1, 8)]
    findings = [F(line=i) for i in range(1, 6)] + [F(line=500)]
    r = score(findings, labels)
    assert (r.tp, r.fp, r.fn) == (5, 1, 2)
    assert round(r.precision, 3) == 0.833
    assert round(r.recall, 3) == 0.714
    assert round(r.f1, 3) == 0.769


def test_perfect_score():
    r = score([F(line=1)], [L(line=1)])
    assert r.precision == r.recall == r.f1 == 1.0


def test_no_findings_means_zero_recall_not_a_crash():
    r = score([], [L()])
    assert (r.tp, r.fn) == (0, 1)
    assert r.recall == 0.0
    assert r.precision == 0.0
    assert r.f1 == 0.0


def test_all_findings_spurious():
    r = score([F(line=1), F(line=2)], [])
    assert (r.tp, r.fp, r.fn) == (0, 2, 0)
    assert r.precision == 0.0


def test_empty_everything_does_not_divide_by_zero():
    r = score([], [])
    assert (r.precision, r.recall, r.f1) == (0.0, 0.0, 0.0)


def test_f1_is_zero_when_either_side_is_zero():
    assert Score(matched=[], missed=[L()], spurious=[F()]).f1 == 0.0


# --- label file -------------------------------------------------------------


def test_real_label_file_loads_and_is_internally_consistent():
    path = pathlib.Path(__file__).parent / "labels" / "vampi.yml"
    target, labels = load_labels(path)

    assert target["commit"] == "f16052dce83f05847133ec98f01c5193a41de7d8"
    assert target["scope"], "scope must be set or the scan reads the whole tree"
    assert len(labels) == 7

    # No duplicate locations: a duplicated label would inflate the denominator.
    locations = [(l.file, l.line) for l in labels]
    assert len(locations) == len(set(locations))

    # Every label is classified, and only into classes the rules cover.
    assert {l.bug_class for l in labels} <= {"bola", "bfla", "mass-assignment"}

    # Paths are target-relative, never absolute or Windows-separated.
    for l in labels:
        assert not l.file.startswith("/")
        assert "\\" not in l.file
        assert l.line > 0


def test_missing_label_file_raises_rather_than_scoring_zero():
    with pytest.raises(FileNotFoundError):
        load_labels(pathlib.Path("benchmark/labels/does-not-exist.yml"))


# --- summariser -------------------------------------------------------------
#
# This runs under `if: always()` in CI, so it must never raise on bad input.
# An exception here would mask whatever actually failed upstream.


def test_summarise_renders_a_row_per_result():
    import summarise

    out = summarise.render([
        {"target": "VAmPI", "labelled": 7, "tp": 5, "fp": 1, "fn": 2,
         "precision": 0.8333, "recall": 0.7143, "f1": 0.7692},
    ])
    assert "| VAmPI | 7 | 5 | 1 | 2 | 0.8333 | 0.7143 | 0.7692 |" in out
    assert out.count("\n|") >= 3  # header, separator, one data row


def test_summarise_missing_dir_is_not_an_error(capsys):
    rc = _run_summarise(["summarise.py", "definitely/not/here"])
    assert rc == 0
    assert "No benchmark results" in capsys.readouterr().out


def test_summarise_ignores_unreadable_json(tmp_path, capsys):
    (tmp_path / "broken.json").write_text("{ not json", encoding="utf-8")
    rc = _run_summarise(["summarise.py", str(tmp_path)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "Could not read" in out


def _run_summarise(argv):
    import sys as _sys

    import summarise

    saved = _sys.argv
    try:
        _sys.argv = argv
        return summarise.main()
    finally:
        _sys.argv = saved
