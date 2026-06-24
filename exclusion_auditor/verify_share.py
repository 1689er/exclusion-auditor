"""Share-safety verifier for sanitized (`--share-out`) reports.

Gives users an in-tool way to *prove* a sanitized report is safe to share before
it leaves their control, instead of trusting the redactor blindly. Runs three
checks against a `--share-out` JSON file:

  1. Schema allowlist  - every finding contains ONLY known-safe keys; no
     forbidden keys (value, created_by, comment, tenant_cid, id, scope, groups...).
  2. Leak scan         - every string value is scanned for path-like / identity-
     like content (drive letters, UNC paths, backslash paths, executable
     extensions, emails, 32-hex CID/client-id GUIDs, dashed GUIDs).
  3. Consistency       - the summary block matches the findings array.

Pure and dependency-free so it unit-tests without a tenant. Reused by the CLI
(`exclusion-auditor --verify-share <file>`).
"""

from __future__ import annotations

import json
import re
from collections import Counter
from typing import List, Tuple

# The exact, exhaustive set of keys a sanitized finding may contain.
SAFE_KEYS = {
    "rule_id", "rule_name", "severity", "base_severity", "escalated", "category",
    "mitre", "type", "pattern_kind", "scope_class", "has_comment", "value_token",
    "suppressed",
}
# Keys that would indicate a leak if they ever appeared in a sanitized finding.
FORBIDDEN_KEYS = {
    "value", "path", "paths", "created_by", "created_at", "modified_on", "comment",
    "comments", "tenant_cid", "cid", "id", "groups", "group", "scope", "hostname",
    "host", "user", "username", "owner",
}

# Reduced-vocabulary values that are intended output, not company data.
SHARED_VOCAB = {"global", "scoped"}

_DRIVE = re.compile(r"[A-Za-z]:[\\/]")
_UNC = re.compile(r"\\\\[^\\]+\\")
_BACKSLASH_PATH = re.compile(r"[A-Za-z0-9_]+\\[A-Za-z0-9_]")
_EXEC_EXT = re.compile(r"\.(exe|dll|ps1|bat|cmd|vbs|js|msi|sys|com|scr)\b", re.I)
_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_CID_GUID = re.compile(r"\b[0-9a-f]{32}\b", re.I)
_DASH_GUID = re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I)
_TOKEN = re.compile(r"^v_[0-9a-f]{10}$")

# Keys whose values are tool-controlled prose (generic rule titles) and may
# legitimately contain words like "executable" without being company data.
_NARRATIVE_KEYS = {"rule_name"}


def _scan_string(key: str, val: str, where: str, issues: List[str]) -> None:
    if key == "value_token":
        if not _TOKEN.match(val):
            issues.append(f"{where}: value_token {val!r} is not the v_<hex10> shape")
        return
    if val in SHARED_VOCAB:
        return
    for label, rx in (("drive-letter path", _DRIVE), ("UNC path", _UNC),
                      ("CID/client-id GUID", _CID_GUID), ("dashed GUID", _DASH_GUID),
                      ("email address", _EMAIL)):
        if rx.search(val):
            issues.append(f"{where}: key {key!r} value looks like a {label}: {val!r}")
    if key not in _NARRATIVE_KEYS:
        if _BACKSLASH_PATH.search(val):
            issues.append(f"{where}: key {key!r} value contains a backslash path: {val!r}")
        if _EXEC_EXT.search(val):
            issues.append(f"{where}: key {key!r} value contains an executable extension: {val!r}")


def verify_doc(doc: dict) -> Tuple[bool, List[str]]:
    """Verify an already-parsed sanitized report. Returns (ok, issues)."""
    issues: List[str] = []

    if "SANITIZED" not in (doc.get("classification") or ""):
        issues.append(f"top-level classification is not SANITIZED: {doc.get('classification')!r}")

    findings = doc.get("findings")
    if not isinstance(findings, list):
        return False, ["'findings' is missing or not a list"]

    for i, f in enumerate(findings):
        where = f"findings[{i}]"
        keys = set(f.keys())
        extra = keys - SAFE_KEYS
        if extra:
            issues.append(f"{where}: unexpected key(s): {sorted(extra)}")
        forbidden = keys & FORBIDDEN_KEYS
        if forbidden:
            issues.append(f"{where}: FORBIDDEN key(s) present: {sorted(forbidden)}")
        if f.get("scope_class") not in ("global", "scoped"):
            issues.append(f"{where}: scope_class={f.get('scope_class')!r} (expected global|scoped)")
        if not isinstance(f.get("has_comment"), bool):
            issues.append(f"{where}: has_comment is not a bool: {f.get('has_comment')!r}")
        for k, v in f.items():
            if isinstance(v, str):
                _scan_string(k, v, where, issues)

    # consistency: recompute the summary from the findings array
    summary = doc.get("summary", {}) or {}
    if summary.get("findings") != len(findings):
        issues.append(f"summary.findings={summary.get('findings')} but {len(findings)} present")
    for label, recomputed in (
        ("by_severity", dict(Counter(f.get("severity") for f in findings))),
        ("by_rule", dict(Counter(f.get("rule_id") for f in findings))),
        ("by_category", dict(Counter(f.get("category") for f in findings))),
    ):
        reported = dict(summary.get(label, {}) or {})
        if recomputed != reported:
            issues.append(f"summary.{label} mismatch: reported={reported} recomputed={recomputed}")

    return (len(issues) == 0), issues


def verify_file(path: str) -> Tuple[bool, List[str]]:
    with open(path, "r", encoding="utf-8") as fh:
        doc = json.load(fh)
    return verify_doc(doc)


def render_result(path: str, ok: bool, issues: List[str], doc: dict) -> str:
    summary = (doc or {}).get("summary", {}) or {}
    findings = (doc or {}).get("findings", []) or []
    lines = [
        "=" * 70,
        f"  SHARE-SAFETY VERIFICATION  ({path})",
        "=" * 70,
        f"  findings:          {len(findings)}",
        f"  distinct tokens:   {len({f.get('value_token') for f in findings})}",
        f"  exclusions scanned:{summary.get('exclusions_scanned')}",
        "-" * 70,
    ]
    if ok:
        lines.append("  RESULT: PASS - only safe fields, no path/identity/CID leakage,")
        lines.append("          summary is internally consistent. Safe to share.")
    else:
        lines.append(f"  RESULT: {len(issues)} ISSUE(S) - review before sharing:")
        lines.extend(f"    - {it}" for it in issues)
    lines.append("=" * 70)
    return "\n".join(lines)


def main(argv=None) -> int:
    import argparse
    p = argparse.ArgumentParser(
        prog="exclusion-auditor-verify",
        description="Verify a sanitized (--share-out) report is safe to share.",
    )
    p.add_argument("file", help="path to the sanitized JSON report")
    args = p.parse_args(argv)
    try:
        with open(args.file, "r", encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"error: could not read {args.file}: {exc}")
        return 2
    ok, issues = verify_doc(doc)
    print(render_result(args.file, ok, issues, doc))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
