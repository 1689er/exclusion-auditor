"""Calibration tests for EXCL-PATH-001 vs. CrowdStrike any-volume prefixes.

A leading `**\\` / `\\Device\\HarddiskVolume*\\` is an addressing convention, not
a near-root wildcard. A filename-anchored value like `**\\Vendor\\app.exe` should
NOT be a drive-root critical; genuinely broad profile-wide subtrees should be.
"""

import os

from exclusion_auditor.adapters.import_adapter import ImportAdapter  # noqa: F401
from exclusion_auditor.datarefs import DataResolver
from exclusion_auditor.engine import Engine
from exclusion_auditor.models import NormalizedExclusion
from exclusion_auditor.paths import wildcard_depth
from exclusion_auditor.rules import load_rules

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def test_wildcard_depth_skips_any_volume_prefix():
    # filename-anchored under an any-volume prefix -> no near-root wildcard
    assert wildcard_depth(r"**\Vendor\app.exe") == -1
    assert wildcard_depth(r"**\Program Files\CyberArk\**") == 2
    # genuinely broad: early wildcard remains after the prefix
    assert wildcard_depth(r"\Device\HarddiskVolume3\Users\*\x\**\*") == 1
    # relative whole-tree and single-* drive stay near-root
    assert wildcard_depth(r"itron\**") == 1
    assert wildcard_depth(r"*\SMSPKG") == 0


def _engine():
    rules = load_rules([os.path.join(ROOT, "rules")])
    data = DataResolver(os.path.join(ROOT, "data"))
    return Engine(rules, data, [])


def _excl(value, scope="global"):
    return NormalizedExclusion(id="x", platform="crowdstrike", type="ml",
                               value=value, pattern_kind="wildcard", scope=scope,
                               comment="documented", created_at="2025-06-01T00:00:00Z")


def _rules_for(value, scope="global"):
    findings = _engine().run([_excl(value, scope)])
    return {f.rule_id: f.severity for f in findings}


def test_filename_anchored_anyvolume_is_not_critical():
    # scoped, to isolate the path rule from global-scope escalation
    r = _rules_for(r"**\Vendor\app.exe", scope="host_group:Vendor")
    assert "EXCL-PATH-001" not in r          # no longer a false drive-root critical
    assert r.get("EXCL-PATH-003") == "medium"  # wildcard-in-path instead


def test_profile_wide_anyvolume_subtree_stays_critical():
    r = _rules_for(r"\Device\HarddiskVolume3\Users\*\AppData\Roaming\Code\**\*")
    assert r.get("EXCL-PATH-001") == "critical"
