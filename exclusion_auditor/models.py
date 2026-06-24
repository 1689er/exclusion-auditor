"""Core data types shared across adapters, engine, and reporters."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

# Severity ladder, low to high. Used for sorting, escalation, and threshold filtering.
SEVERITIES = ["info", "low", "medium", "high", "critical"]


def severity_rank(sev: str) -> int:
    try:
        return SEVERITIES.index(sev)
    except ValueError:
        return 0


def bump_severity(sev: str, steps: int = 1) -> str:
    """Raise a severity by `steps`, capped at the top of the ladder."""
    idx = min(severity_rank(sev) + steps, len(SEVERITIES) - 1)
    return SEVERITIES[idx]


@dataclass
class NormalizedExclusion:
    """A single exclusion mapped into a vendor-agnostic shape.

    Every adapter (CrowdStrike, import, ...) produces these. The engine only
    ever sees this type, which is what keeps the rules vendor-neutral.
    """

    id: str
    platform: str
    type: str                       # ml | ioa | sensor_visibility | path | extension | process
    value: str
    pattern_kind: str = "path"      # path | wildcard | extension | process | hash
    scope: str = "global"           # "global" or "host_group:<name>"
    tenant_cid: str = ""
    created_by: str = ""
    created_at: str = ""            # ISO-8601 string, optional
    comment: str = ""

    @classmethod
    def from_dict(cls, d: dict) -> "NormalizedExclusion":
        return cls(
            id=str(d.get("id", "")),
            platform=str(d.get("platform", "import")),
            type=str(d.get("type", "path")),
            value=str(d.get("value", "")),
            pattern_kind=str(d.get("pattern_kind", "path")),
            scope=str(d.get("scope", "global")),
            tenant_cid=str(d.get("tenant_cid", "")),
            created_by=str(d.get("created_by", "")),
            created_at=str(d.get("created_at", "")),
            comment=str(d.get("comment", "")),
        )


@dataclass
class Finding:
    """One rule firing against one exclusion."""

    rule_id: str
    rule_name: str
    severity: str
    category: str
    exclusion: NormalizedExclusion
    remediation: str = ""
    mitre: str = ""
    base_severity: str = ""          # severity before any escalation
    escalated: bool = False
    escalation_note: str = ""
    suppressed: bool = False
    suppression_reason: str = ""
    references: list = field(default_factory=list)
