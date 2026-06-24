"""Redaction tests. The critical guarantee: a sanitized report must contain
none of the sensitive values present in the source exclusions."""

import json
import os

from exclusion_auditor import cli
from exclusion_auditor.adapters.import_adapter import ImportAdapter
from exclusion_auditor.datarefs import DataResolver
from exclusion_auditor.engine import Engine
from exclusion_auditor.redact import build_share_report, load_or_create_salt, scan_for_sensitive
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


# --- safety scanner (issues #2/#3/#7) ------------------------------------

def test_scan_flags_planted_sensitive_content():
    text = r'path C:\Users\jdoe\secret.exe contact admin@corp.com'
    hits = dict(scan_for_sensitive(text))
    assert "windows_path" in hits
    assert "email_address" in hits


def test_sanitized_report_scans_clean():
    # regression: the share scanner must find nothing in a sanitized report
    findings, total = _findings()
    blob = json.dumps(build_share_report(findings, total))
    assert scan_for_sensitive(blob) == []


# --- persistent salt (issue #8) ------------------------------------------

def test_persistent_salt_gives_stable_tokens(tmp_path):
    findings, total = _findings()
    salt_path = str(tmp_path / "tokens.salt")
    s1 = load_or_create_salt(salt_path)
    s2 = load_or_create_salt(salt_path)   # second call reads the same salt
    assert s1 == s2
    t1 = sorted(f["value_token"] for f in build_share_report(findings, total, salt=s1)["findings"])
    t2 = sorted(f["value_token"] for f in build_share_report(findings, total, salt=s2)["findings"])
    assert t1 == t2


# --- CLI safety features (issues #2/#5) ----------------------------------

def test_cli_summary_only(monkeypatch, capsys):
    monkeypatch.chdir(ROOT)
    rc = cli.main(["--config", "examples/demo.yaml", "--summary-only", "--format", "json"])
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    assert data["findings"] == []
    assert data["summary"]["findings"] > 0
    assert "SANITIZED" in data["classification"]


def test_cli_verify_share_safe(tmp_path):
    f = tmp_path / "ok.json"
    f.write_text('{"value_token":"v_abc1234567","scope_class":"global","severity":"low"}')
    assert cli.main(["--verify-share", str(f)]) == 0


def test_cli_verify_share_unsafe(tmp_path):
    f = tmp_path / "bad.json"
    f.write_text(r'{"value":"C:\Users\jdoe\payload.exe","created_by":"j.admin"}')
    assert cli.main(["--verify-share", str(f)]) == 1


def test_cli_verify_share_catches_utf16(tmp_path):
    # PowerShell `>` emits UTF-16; the scanner must still see the sensitive content.
    f = tmp_path / "bad_utf16.json"
    f.write_bytes(r'{"value":"C:\Users\jdoe\x.exe"}'.encode("utf-16"))
    assert cli.main(["--verify-share", str(f)]) == 1


def test_cli_share_out_autoverifies(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(ROOT)
    out = tmp_path / "s.json"
    rc = cli.main(["--config", "examples/demo.yaml", "--share-out", str(out)])
    assert rc == 0
    assert "auto-verified" in capsys.readouterr().err
    assert scan_for_sensitive(out.read_text()) == []
