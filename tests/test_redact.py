"""Redaction tests. The critical guarantee: a sanitized report must contain
none of the sensitive values present in the source exclusions."""

import json
import os

from exclusion_auditor.adapters.import_adapter import ImportAdapter
from exclusion_auditor.datarefs import DataResolver
from exclusion_auditor.engine import Engine
from exclusion_auditor.redact import build_share_report
from exclusion_auditor.rules import load_rules
from exclusion_auditor.suppressions import load_suppressions

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Sensitive substrings that appear in the demo exclusion set and MUST NOT survive
# into a sanitized report.
SENSITIVE = [
    "powershell.exe",
    "AppData",
    "LineOfBusinessApp",
    "service.exe",
    "Workstations",   # host group name
    "AppServers",
    "j.admin",        # created_by
    "automation-team",
    "legacy-import",
    "Vendor agent",   # comment text
    "SEC-1042",       # ticket in a comment
    "C:\\",
]


def _findings():
    exclusions = ImportAdapter({"path": os.path.join(ROOT, "examples", "sample-exclusions.json")}).fetch()
    rules = load_rules([os.path.join(ROOT, "rules")])
    data = DataResolver(os.path.join(ROOT, "data"))
    supp = load_suppressions(os.path.join(ROOT, "examples", "suppressions.yml"))
    return Engine(rules, data, supp).run(exclusions), len(exclusions)


def test_no_sensitive_values_leak():
    findings, total = _findings()
    blob = json.dumps(build_share_report(findings, total))
    for s in SENSITIVE:
        assert s not in blob, f"sensitive value leaked into sanitized report: {s!r}"


def test_redacted_fields_are_stripped():
    findings, total = _findings()
    share = build_share_report(findings, total)
    for f in share["findings"]:
        assert "value" not in f                 # raw value never present
        assert "created_by" not in f
        assert "comment" not in f
        assert f["scope_class"] in ("global", "scoped")   # never a group name
        assert f["value_token"].startswith("v_")


def test_same_value_gets_same_token_within_report():
    # demo-003 "C:\*" trips two rules (EXCL-PATH-001 and EXCL-PATH-004);
    # both should carry the same token so correlation is preserved.
    findings, total = _findings()
    share = build_share_report(findings, total)
    tokens = {f["rule_id"]: f["value_token"]
              for f in share["findings"] if f["rule_id"] in ("EXCL-PATH-001", "EXCL-PATH-004")}
    assert tokens["EXCL-PATH-001"] == tokens["EXCL-PATH-004"]


def test_distinct_values_get_distinct_tokens():
    findings, total = _findings()
    share = build_share_report(findings, total)
    by_rule = {f["rule_id"]: f["value_token"] for f in share["findings"]}
    # *.ps1 (EXCL-EXT-001) and C:\* (EXCL-PATH-001) are different values
    assert by_rule["EXCL-EXT-001"] != by_rule["EXCL-PATH-001"]


def test_summary_counts_present():
    findings, total = _findings()
    share = build_share_report(findings, total)
    s = share["summary"]
    assert s["exclusions_scanned"] == total
    assert s["findings"] == len(share["findings"])
    assert sum(s["by_severity"].values()) == s["findings"]
    assert "SANITIZED" in share["classification"]
