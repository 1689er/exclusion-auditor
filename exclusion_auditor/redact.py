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
import os
import re
import secrets
from collections import Counter
from typing import List, Optional, Tuple

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


def load_or_create_salt(path: str) -> bytes:
    """Read a persistent salt (hex) from `path`, creating it if missing.

    A persistent salt makes value tokens stable across runs so findings can be
    tracked over time (issue #8). The salt enables correlation, so keep it private
    (it's git-ignored by default) — but it never reveals the underlying values.
    """
    if os.path.isfile(path):
        with open(path, "r", encoding="utf-8") as fh:
            return bytes.fromhex(fh.read().strip())
    salt = secrets.token_bytes(16)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(salt.hex())
    return salt


# Patterns that should NEVER appear in a shareable report. Used by `--verify-share`
# to catch accidental sharing of raw/confidential output (issues #2, #7).
_SENSITIVE_PATTERNS = [
    ("windows_path", re.compile(r"[A-Za-z]:\\")),
    ("unc_path", re.compile(r"\\\\[A-Za-z0-9_.$-]+\\")),
    ("user_profile_path", re.compile(r"[Uu]sers[\\/][^\\/\"\s]+")),
    ("email_address", re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")),
    ("guid", re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                        r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")),
    ("long_hex_32", re.compile(r"\b[0-9a-f]{32}\b")),
    ("created_by_field", re.compile(r'"created_by"\s*:')),
]


def scan_for_sensitive(text: str) -> List[Tuple[str, str]]:
    """Return (pattern_name, sample) for each sensitive pattern found in `text`.
    Empty list => no obvious sensitive content (safe to share)."""
    hits = []
    for name, rx in _SENSITIVE_PATTERNS:
        m = rx.search(text)
        if m:
            sample = m.group(0)
            hits.append((name, sample[:40] + ("..." if len(sample) > 40 else "")))
    return hits


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
                       salt: Optional[bytes] = None) -> dict:
    """A fully sanitized, shareable report: aggregate summary + redacted findings."""
    salt = salt or secrets.token_bytes(16)
    active = [f for f in findings if not f.suppressed]
    redacted = [redact_finding(f, salt) for f in sort_findings(active)]

    by_sev = Counter(r["severity"] for r in redacted)
    by_rule = Counter(r["rule_id"] for r in redacted)
    by_cat = Counter(r["category"] for r in redacted)

    return {
        "classification": CLASSIFICATION,
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
        "findings": redacted,
    }
