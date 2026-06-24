"""End-to-end engine tests against the bundled demo set. These lock in the
calibrated behavior so rules can't silently regress as the library grows."""

import os

from exclusion_auditor.adapters.import_adapter import ImportAdapter
from exclusion_auditor.datarefs import DataResolver
from exclusion_auditor.engine import Engine
from exclusion_auditor.rules import load_rules
from exclusion_auditor.suppressions import load_suppressions

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _run():
    exclusions = ImportAdapter({"path": os.path.join(ROOT, "examples", "sample-exclusions.json")}).fetch()
    rules = load_rules([os.path.join(ROOT, "rules")])
    data = DataResolver(os.path.join(ROOT, "data"))
    supp = load_suppressions(os.path.join(ROOT, "examples", "suppressions.yml"))
    findings = Engine(rules, data, supp).run(exclusions)
    return exclusions, findings


def _active(findings):
    return [f for f in findings if not f.suppressed]


def test_demo_has_expected_active_count():
    _, findings = _run()
    assert len(_active(findings)) == 12


def test_good_exclusion_is_clean():
    # demo-005 is signed, scoped, documented, recent -> must produce nothing.
    _, findings = _run()
    assert [f for f in _active(findings) if f.exclusion.id == "demo-005"] == []


def test_documented_writable_is_suppressed_only():
    # demo-002 fires EXCL-PATH-002 but it is suppressed; no other active finding.
    _, findings = _run()
    active = [f for f in _active(findings) if f.exclusion.id == "demo-002"]
    assert active == []
    suppressed = [f for f in findings if f.suppressed and f.exclusion.id == "demo-002"]
    assert len(suppressed) == 1
    assert suppressed[0].rule_id == "EXCL-PATH-002"


def test_process_rule_never_fires_on_file_exclusions():
    # Regression: EXCL-PROC-002 must not match ml/extension/path exclusions.
    _, findings = _run()
    for f in findings:
        if f.rule_id == "EXCL-PROC-002":
            assert f.exclusion.type in ("process", "ioa")


def test_root_exclusion_is_critical():
    _, findings = _run()
    crit = [f for f in _active(findings)
            if f.exclusion.id == "demo-003" and f.rule_id == "EXCL-PATH-001"]
    assert len(crit) == 1
    assert crit[0].severity == "critical"


def test_global_scope_escalates_process_finding():
    # demo-004 powershell.exe IOA at global scope: high -> critical.
    _, findings = _run()
    proc = [f for f in _active(findings)
            if f.exclusion.id == "demo-004" and f.rule_id == "EXCL-PROC-001"]
    assert len(proc) == 1
    assert proc[0].escalated is True
    assert proc[0].severity == "critical"
    assert proc[0].base_severity == "high"
