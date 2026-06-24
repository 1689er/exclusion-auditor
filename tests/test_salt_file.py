"""Tests for the persisted (keyed) redaction salt: load_or_create_salt."""

import os

from exclusion_auditor.models import Finding, NormalizedExclusion
from exclusion_auditor.redact import build_share_report, load_or_create_salt


def _make(value):
    excl = NormalizedExclusion(
        id="x", platform="crowdstrike", type="ml", value=value,
        pattern_kind="wildcard", scope="global",
    )
    return Finding(
        rule_id="EXCL-PATH-001", rule_name="Root or near-root path excluded",
        severity="critical", category="path", exclusion=excl, mitre="T1562.001",
        base_severity="critical",
    )


def test_salt_file_is_created_then_reused(tmp_path):
    p = str(tmp_path / "audit.salt")
    assert not os.path.exists(p)
    s1 = load_or_create_salt(p)
    assert os.path.exists(p)
    assert len(s1) >= 16
    s2 = load_or_create_salt(p)          # second call reuses the same bytes
    assert s1 == s2


def test_persisted_salt_yields_stable_tokens_across_runs(tmp_path):
    p = str(tmp_path / "audit.salt")
    salt = load_or_create_salt(p)
    a = build_share_report([_make("C:\\*")], total_exclusions=1, salt=salt)
    b = build_share_report([_make("C:\\*")], total_exclusions=1, salt=salt)
    assert a["findings"][0]["value_token"] == b["findings"][0]["value_token"]


def test_per_run_salt_differs_from_persisted(tmp_path):
    p = str(tmp_path / "audit.salt")
    salt = load_or_create_salt(p)
    keyed = build_share_report([_make("C:\\*")], total_exclusions=1, salt=salt)
    # No salt -> fresh random salt -> token should (overwhelmingly) differ
    fresh = build_share_report([_make("C:\\*")], total_exclusions=1)
    assert keyed["findings"][0]["value_token"] != fresh["findings"][0]["value_token"]


def test_empty_salt_file_is_rejected(tmp_path):
    p = tmp_path / "audit.salt"
    p.write_bytes(b"")
    try:
        load_or_create_salt(str(p))
        assert False, "expected ValueError for empty salt file"
    except ValueError:
        pass
