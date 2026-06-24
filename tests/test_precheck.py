"""Tests for the read-only scope pre-check. The pure classifier and the
non-CrowdStrike short-circuit are tested without falconpy or a live tenant."""

import os

from exclusion_auditor import precheck

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def test_classify_states():
    assert precheck._classify({"status_code": 200, "body": {"resources": []}})[0] == "OK"
    assert precheck._classify({"status_code": 401, "body": {}})[0] == "AUTH"
    assert precheck._classify({"status_code": 403,
                               "body": {"errors": [{"message": "denied"}]}})[0] == "MISSING"
    assert precheck._classify({"status_code": 500, "body": {}})[0] == "ERROR"


def test_run_skips_non_crowdstrike(capsys):
    rc = precheck.run(os.path.join(ROOT, "examples", "demo.yaml"))
    assert rc == 0
    assert "nothing to check" in capsys.readouterr().out
