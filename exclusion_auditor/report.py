"""Reporters: console table, JSON, and Markdown."""

from __future__ import annotations

import json
from typing import List

from .engine import sort_findings
from .models import Finding, severity_rank

SEV_LABEL = {
    "critical": "CRIT",
    "high": "HIGH",
    "medium": "MED ",
    "low": "LOW ",
    "info": "INFO",
}


def _active(findings: List[Finding]) -> List[Finding]:
    return [f for f in findings if not f.suppressed]


def _suppressed(findings: List[Finding]) -> List[Finding]:
    return [f for f in findings if f.suppressed]


def render(findings: List[Finding], fmt: str, total_exclusions: int) -> str:
    if fmt == "json":
        return _render_json(findings, total_exclusions)
    if fmt == "markdown":
        return _render_markdown(findings, total_exclusions)
    return _render_table(findings, total_exclusions)


# --- table ---------------------------------------------------------------

def _render_finding_detail(lines, f):
    flag = " *escalated*" if f.escalated else ""
    lines.append(f"  [{SEV_LABEL[f.severity]}] {f.rule_id}  {f.rule_name}{flag}")
    lines.append(f"         exclusion : {f.exclusion.value}  ({f.exclusion.type}, scope={f.exclusion.scope})")
    if f.mitre:
        lines.append(f"         mitre     : {f.mitre}")
    if f.escalation_note:
        lines.append(f"         note      : {f.escalation_note}")
    lines.append(f"         fix       : {f.remediation.strip()}")
    lines.append("")


def _render_table(findings, total_exclusions) -> str:
    active = sort_findings(_active(findings))
    suppressed = _suppressed(findings)
    # Separate genuine risk from low-severity hygiene so the signal isn't buried.
    risk = [f for f in active if f.category != "hygiene"]
    hygiene = [f for f in active if f.category == "hygiene"]

    lines = []
    lines.append("=" * 78)
    lines.append("  EXCLUSION AUDIT REPORT")
    lines.append("  CONFIDENTIAL - contains exclusion values & admin identities.")
    lines.append("  Use --redact or --share-out to produce a shareable version.")
    lines.append("=" * 78)

    counts = {}
    for f in active:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    summary = "  ".join(
        f"{SEV_LABEL[s].strip()}:{counts.get(s, 0)}"
        for s in ["critical", "high", "medium", "low", "info"]
    )
    lines.append(f"  Exclusions scanned: {total_exclusions}    Findings: {len(active)}"
                 f"   (Risk: {len(risk)}  Hygiene: {len(hygiene)})")
    lines.append(f"  {summary}")
    if suppressed:
        lines.append(f"  (+{len(suppressed)} suppressed)")
    lines.append("-" * 78)

    # Risk findings: full detail.
    lines.append(f"  RISK FINDINGS ({len(risk)})")
    lines.append("")
    if not risk:
        lines.append("  none")
        lines.append("")
    for f in risk:
        _render_finding_detail(lines, f)

    # Hygiene: compact counts (full detail available via --format json).
    if hygiene:
        lines.append("-" * 78)
        lines.append(f"  HYGIENE ({len(hygiene)}) - low-severity governance; compact view "
                     "(use --format json for full detail)")
        grouped = {}
        for f in hygiene:
            entry = grouped.setdefault(f.rule_id, [f.rule_name, 0])
            entry[1] += 1
        for rid, (name, cnt) in sorted(grouped.items(), key=lambda kv: -kv[1][1]):
            lines.append(f"    {cnt:>5}  {rid}  {name}")
        lines.append("")

    if suppressed:
        lines.append("-" * 78)
        lines.append("  SUPPRESSED (reviewed & accepted - still shown for re-review)")
        for f in suppressed:
            lines.append(f"  [{SEV_LABEL[f.base_severity or f.severity]}] {f.rule_id}  {f.exclusion.value}")
            lines.append(f"         reason    : {f.suppression_reason.strip()}")
        lines.append("")
    lines.append("=" * 78)
    return "\n".join(lines)


# --- json ----------------------------------------------------------------

def _finding_dict(f: Finding) -> dict:
    return {
        "rule_id": f.rule_id,
        "rule_name": f.rule_name,
        "severity": f.severity,
        "base_severity": f.base_severity,
        "escalated": f.escalated,
        "category": f.category,
        "mitre": f.mitre,
        "suppressed": f.suppressed,
        "suppression_reason": f.suppression_reason,
        "remediation": f.remediation,
        "references": f.references,
        "exclusion": {
            "id": f.exclusion.id,
            "platform": f.exclusion.platform,
            "type": f.exclusion.type,
            "value": f.exclusion.value,
            "pattern_kind": f.exclusion.pattern_kind,
            "scope": f.exclusion.scope,
            "created_by": f.exclusion.created_by,
            "created_at": f.exclusion.created_at,
        },
    }


def _render_json(findings, total_exclusions) -> str:
    active = sort_findings(_active(findings))
    payload = {
        "summary": {
            "exclusions_scanned": total_exclusions,
            "findings": len(active),
            "suppressed": len(_suppressed(findings)),
        },
        "findings": [_finding_dict(f) for f in active],
        "suppressed": [_finding_dict(f) for f in _suppressed(findings)],
    }
    return json.dumps(payload, indent=2)


# --- markdown ------------------------------------------------------------

def _render_markdown(findings, total_exclusions) -> str:
    active = sort_findings(_active(findings))
    out = ["# Exclusion Audit Report", ""]
    out.append(f"- Exclusions scanned: **{total_exclusions}**")
    out.append(f"- Findings: **{len(active)}**  (suppressed: {len(_suppressed(findings))})")
    out.append("")
    out.append("| Severity | Rule | Exclusion | Type | Scope | MITRE |")
    out.append("|----------|------|-----------|------|-------|-------|")
    for f in active:
        sev = f.severity.upper() + ("*" if f.escalated else "")
        out.append(
            f"| {sev} | {f.rule_id} {f.rule_name} | `{f.exclusion.value}` | "
            f"{f.exclusion.type} | {f.exclusion.scope} | {f.mitre} |"
        )
    return "\n".join(out)


def max_severity(findings: List[Finding]) -> str:
    active = _active(findings)
    if not active:
        return "info"
    return max(active, key=lambda f: severity_rank(f.severity)).severity


# --- sanitized (shareable) rendering -------------------------------------

def render_sanitized(share: dict, fmt: str) -> str:
    if fmt == "json":
        return json.dumps(share, indent=2)
    if fmt == "markdown":
        return _render_sanitized_markdown(share)
    return _render_sanitized_table(share)


def _sev_summary_line(by_severity: dict) -> str:
    return "  ".join(
        f"{SEV_LABEL[s].strip()}:{by_severity.get(s, 0)}"
        for s in ["critical", "high", "medium", "low", "info"]
    )


def _render_sanitized_table(share: dict) -> str:
    s = share["summary"]
    lines = []
    lines.append("=" * 78)
    lines.append("  EXCLUSION AUDIT REPORT - SANITIZED (safe to share)")
    lines.append("=" * 78)
    lines.append("  " + share["classification"])
    lines.append(f"  Exclusions scanned: {s['exclusions_scanned']}    "
                 f"Findings: {s['findings']}    Suppressed: {s['suppressed']}")
    lines.append("  " + _sev_summary_line(s["by_severity"]))
    lines.append("-" * 78)
    lines.append("  SEV   RULE          TYPE / PATTERN        SCOPE    VALUE TOKEN")
    for f in share["findings"]:
        flag = "*" if f["escalated"] else " "
        lines.append(
            "  {sev:<5}{flag} {rule:<13} {tp:<21} {scope:<8} {tok}".format(
                sev=SEV_LABEL[f["severity"]].strip(), flag=flag, rule=f["rule_id"],
                tp=f'{f["type"]}/{f["pattern_kind"]}', scope=f["scope_class"],
                tok=f["value_token"],
            )
        )
    lines.append("=" * 78)
    return "\n".join(lines)


def _render_sanitized_markdown(share: dict) -> str:
    s = share["summary"]
    out = ["# Exclusion Audit Report — SANITIZED", "", f"> {share['classification']}", ""]
    out.append(f"- Exclusions scanned: **{s['exclusions_scanned']}**")
    out.append(f"- Findings: **{s['findings']}**  (suppressed: {s['suppressed']})")
    out.append("")
    out.append("| Severity | Rule | Type/Pattern | Scope | Value token |")
    out.append("|----------|------|--------------|-------|-------------|")
    for f in share["findings"]:
        sev = f["severity"].upper() + ("*" if f["escalated"] else "")
        out.append(f"| {sev} | {f['rule_id']} | {f['type']}/{f['pattern_kind']} | "
                   f"{f['scope_class']} | `{f['value_token']}` |")
    return "\n".join(out)
