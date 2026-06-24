"""Sanitization for safe sharing.

Enterprise users must be able to share findings (e.g. to report a false positive
upstream) without leaking company data. This module produces a report that
contains NO exclusion values, paths, admin identities, comments, host group
names, or tenant identifiers.

Each exclusion value is replaced by a per-run hashed token so correlation is
preserved *within* a report ("these 3 findings are the same exclusion") while the
value itself is irreversible. The salt is random per run and never stored, so
tokens cannot be correlated across reports or brute-forced back to a value.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from collections import Counter
from typing import List, Optional

from . import __version__
from .engine import sort_findings
from .models import SEVERITIES, Finding

CLASSIFICATION = (
    "SANITIZED - safe to share. Contains no exclusion values, paths, identities, "
    "host group names, comments, or tenant IDs."
)


def _token(salt: bytes, value: str) -> str:
    digest = hmac.new(salt, (value or "").strip().lower().encode("utf-8"), hashlib.sha256)
    return "v_" + digest.hexdigest()[:10]


def redact_finding(f: Finding, salt: bytes) -> dict:
    """Keep only non-identifying, analytically-useful fields."""
    return {
        "rule_id": f.rule_id,
        "rule_name": f.rule_name,          # generic rule title, not customer data
        "severity": f.severity,
        "base_severity": f.base_severity,
        "escalated": f.escalated,
        "category": f.category,
        "mitre": f.mitre,
        "type": f.exclusion.type,
        "pattern_kind": f.exclusion.pattern_kind,
        # scope reduced to a class so host group NAMES never leak
        "scope_class": "global" if f.exclusion.scope == "global" else "scoped",
        "has_comment": bool((f.exclusion.comment or "").strip()),
        "value_token": _token(salt, f.exclusion.value),
        "suppressed": f.suppressed,
    }


def build_share_report(findings: List[Finding], total_exclusions: int,
                       salt: Optional[bytes] = None,
                       summary_only: bool = False) -> dict:
    """A fully sanitized, shareable report: aggregate summary + redacted findings.

    When ``summary_only`` is True the per-finding rows are omitted entirely and
    only the aggregate summary (counts by severity/rule/category) is returned -
    the lowest-risk contribution shape for environments whose data-handling
    policy balks even at per-finding hashed tokens.
    """
    salt = salt or secrets.token_bytes(16)
    active = [f for f in findings if not f.suppressed]
    redacted = [redact_finding(f, salt) for f in sort_findings(active)]

    by_sev = Counter(r["severity"] for r in redacted)
    by_rule = Counter(r["rule_id"] for r in redacted)
    by_cat = Counter(r["category"] for r in redacted)

    classification = CLASSIFICATION
    if summary_only:
        classification = (
            "SANITIZED (summary only) - safe to share. Aggregate counts only; "
            "no per-finding rows, values, paths, identities, host group names, "
            "comments, or tenant IDs."
        )

    return {
        "classification": classification,
        "generated_by": f"exclusion-auditor {__version__}",
        "summary": {
            "exclusions_scanned": total_exclusions,
            "findings": len(redacted),
            "suppressed": sum(1 for f in findings if f.suppressed),
            # ordered high -> low for readability
            "by_severity": {s: by_sev[s] for s in reversed(SEVERITIES) if by_sev[s]},
            "by_rule": dict(by_rule.most_common()),
            "by_category": dict(by_cat.most_common()),
        },
        "findings": [] if summary_only else redacted,
    }
