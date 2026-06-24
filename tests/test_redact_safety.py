"""Redaction safety regression tests.

`redact.redact_finding` hand-builds the sanitized dict, so a future field added
to NormalizedExclusion / Finding could silently start leaking into shared
reports. These tests are the safety net:

  * a unique sentinel is injected into EVERY confidential field, and we assert
    none of those sentinels survive into the serialized share report;
  * the sanitized finding keys are pinned to an exact allowlist (a new leaking
    key fails the test);
  * value -> token is deterministic within a run and collision-free (a bijection
    over distinct values).
"""

import json

from exclusion_auditor.models import Finding, NormalizedExclusion
from exclusion_auditor.redact import build_share_report, redact_finding

# The exact keys a sanitized finding may expose. If redaction starts emitting a
# new key, update this set ONLY after confirming the new key carries no company
# data — that is the point of the gate.
ALLOWED_KEYS = {
    "rule_id", "rule_name", "severity", "base_severity", "escalated", "category",
    "mitre", "type", "pattern_kind", "scope_class", "has_comment", "value_token",
    "suppressed",
}

# Unique, unmistakable sentinels per confidential field.
SENTINELS = {
    "value": "SENTINEL_VALUE_zzz1",
    "scope": "host_group:SENTINEL_GROUP_zzz2",
    "tenant_cid": "SENTINEL_CID_zzz3",
    "created_by": "SENTINEL_ADMIN_zzz4",
    "created_at": "SENTINEL_DATE_zzz5",
    "comment": "SENTINEL_COMMENT_zzz6",
    "id": "SENTINEL_ID_zzz7",
}


def _spiked_finding():
    excl = NormalizedExclusion(
        id=SENTINELS["id"],
        platform="crowdstrike",
        type="ml",
        value=SENTINELS["value"],
        pattern_kind="wildcard",
        scope=SENTINELS["scope"],
        tenant_cid=SENTINELS["tenant_cid"],
        created_by=SENTINELS["created_by"],
        created_at=SENTINELS["created_at"],
        comment=SENTINELS["comment"],
    )
    return Finding(
        rule_id="EXCL-PATH-001", rule_name="Root or near-root path excluded",
        severity="critical", category="path", exclusion=excl, mitre="T1562.001",
        base_severity="critical",
    )


def test_no_confidential_sentinel_survives_redaction():
    doc = build_share_report([_spiked_finding()], total_exclusions=1)
    blob = json.dumps(doc)
    for field, sentinel in SENTINELS.items():
        assert sentinel not in blob, f"confidential field {field!r} leaked into share report"


def test_sanitized_keys_are_pinned_to_allowlist():
    out = redact_finding(_spiked_finding(), salt=b"fixed-salt-for-test")
    extra = set(out.keys()) - ALLOWED_KEYS
    assert not extra, f"redaction emitted unexpected key(s): {extra}"
    # scope must be reduced to a class, never the raw host_group:<name>
    assert out["scope_class"] == "scoped"


def test_token_is_deterministic_within_a_run_and_collision_free():
    salt = b"fixed-salt-for-test"
    a1 = redact_finding(_make("C:\\*"), salt)["value_token"]
    a2 = redact_finding(_make("C:\\*"), salt)["value_token"]
    b = redact_finding(_make("D:\\data"), salt)["value_token"]
    assert a1 == a2          # same value -> same token (faithful)
    assert a1 != b           # different value -> different token (no collision)


def test_value_token_bijection_over_distinct_values():
    findings = [_make(v) for v in ("C:\\*", "D:\\data", "C:\\*", "*.ps1", "D:\\data")]
    doc = build_share_report(findings, total_exclusions=5)
    pairs = {(f["value_token"]) for f in doc["findings"]}
    # 3 distinct values -> exactly 3 distinct tokens
    assert len(pairs) == 3


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
