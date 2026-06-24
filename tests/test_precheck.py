"""Tests for the read-only scope pre-check classifier (no tenant needed)."""

from exclusion_auditor.precheck import _classify


def test_ok_on_2xx_no_errors():
    state, _ = _classify({"status_code": 200, "body": {"resources": []}})
    assert state == "OK"


def test_missing_scope_on_403():
    state, detail = _classify({
        "status_code": 403,
        "body": {"errors": [{"message": "access denied, authorization failed"}]},
    })
    assert state == "MISSING"
    assert "authorization" in detail


def test_auth_on_401():
    state, _ = _classify({"status_code": 401, "body": {"errors": [{"message": "unauthorized"}]}})
    assert state == "AUTH"


def test_error_on_500():
    state, _ = _classify({"status_code": 500, "body": {}})
    assert state == "ERROR"


def test_error_when_body_has_errors_despite_200():
    state, _ = _classify({"status_code": 200, "body": {"errors": [{"message": "boom"}]}})
    assert state == "ERROR"
