"""Tests for the share-safety verifier (exclusion_auditor.verify_share)."""

from exclusion_auditor.models import Finding, NormalizedExclusion
from exclusion_auditor.redact import build_share_report
from exclusion_auditor.verify_share import verify_doc


def _finding(value, scope="global", comment="", rule="EXCL-PATH-001",
             severity="critical", category="path"):
    excl = NormalizedExclusion(
        id="abc", platform="crowdstrike", type="ml", value=value,
        pattern_kind="wildcard", scope=scope, tenant_cid="CID123",
        created_by="admin@example.com", created_at="2020-01-01T00:00:00Z",
        comment=comment,
    )
    return Finding(
        rule_id=rule, rule_name="Root or near-root path excluded", severity=severity,
        category=category, exclusion=excl, mitre="T1562.001", base_severity=severity,
    )


def test_real_share_report_passes():
    findings = [
        _finding("C:\\*", scope="global"),
        _finding("C:\\Users\\bob\\AppData\\Local\\Temp", scope="host_group:Workstations"),
        _finding("powershell.exe", scope="global", comment="documented"),
    ]
    doc = build_share_report(findings, total_exclusions=3)
    ok, issues = verify_doc(doc)
    assert ok, issues


def test_forbidden_key_is_caught():
    doc = build_share_report([_finding("C:\\*")], total_exclusions=1)
    doc["findings"][0]["value"] = "C:\\*"  # inject a raw value (leak)
    ok, issues = verify_doc(doc)
    assert not ok
    assert any("FORBIDDEN" in i for i in issues)


def test_leaked_path_value_is_caught():
    doc = build_share_report([_finding("C:\\*")], total_exclusions=1)
    # smuggle a path into an allowed field
    doc["findings"][0]["rule_id"] = "C:\\Windows\\System32"
    ok, issues = verify_doc(doc)
    assert not ok
    assert any("drive-letter path" in i for i in issues)


def test_bad_token_shape_is_caught():
    doc = build_share_report([_finding("C:\\*")], total_exclusions=1)
    doc["findings"][0]["value_token"] = "not-a-token"
    ok, issues = verify_doc(doc)
    assert not ok
    assert any("value_token" in i for i in issues)


def test_inconsistent_summary_is_caught():
    doc = build_share_report([_finding("C:\\*")], total_exclusions=1)
    doc["summary"]["findings"] = 999
    ok, issues = verify_doc(doc)
    assert not ok
    assert any("summary.findings" in i for i in issues)


def test_cid_guid_leak_is_caught():
    doc = build_share_report([_finding("C:\\*")], total_exclusions=1)
    doc["findings"][0]["mitre"] = "0123456789abcdef0123456789abcdef"  # CID-shaped
    ok, issues = verify_doc(doc)
    assert not ok
    assert any("CID" in i for i in issues)
