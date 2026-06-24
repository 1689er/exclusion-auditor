"""Tests for the --summary-only sanitized share mode."""

from exclusion_auditor.models import Finding, NormalizedExclusion
from exclusion_auditor.redact import build_share_report


def _make(value, severity="critical", rule="EXCL-PATH-001", category="path"):
    excl = NormalizedExclusion(
        id="x", platform="crowdstrike", type="ml", value=value,
        pattern_kind="wildcard", scope="global",
    )
    return Finding(
        rule_id=rule, rule_name="Root or near-root path excluded", severity=severity,
        category=category, exclusion=excl, mitre="T1562.001", base_severity=severity,
    )


def _findings():
    return [_make("C:\\*"), _make("D:\\data"),
            _make("*.ps1", severity="low", rule="EXCL-HYG-001", category="hygiene")]


def test_summary_only_drops_finding_rows_but_keeps_counts():
    doc = build_share_report(_findings(), total_exclusions=3, summary_only=True)
    assert doc["findings"] == []
    # aggregate counts still reflect all findings
    assert doc["summary"]["findings"] == 3
    assert doc["summary"]["by_severity"] == {"critical": 2, "low": 1}
    assert doc["summary"]["by_rule"]["EXCL-PATH-001"] == 2
    assert "summary only" in doc["classification"].lower()


def test_full_mode_still_includes_rows():
    doc = build_share_report(_findings(), total_exclusions=3, summary_only=False)
    assert len(doc["findings"]) == 3


def test_summary_only_leaks_nothing():
    import json
    doc = build_share_report(_findings(), total_exclusions=3, summary_only=True)
    blob = json.dumps(doc)
    for raw in ("C:\\*", "D:\\data", "*.ps1"):
        assert raw not in blob
