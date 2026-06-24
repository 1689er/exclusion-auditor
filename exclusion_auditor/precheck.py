"""Read-only scope pre-check for the CrowdStrike adapter.

Verifies the configured Falcon API client can actually READ the collections the
auditor needs, WITHOUT pulling the full inventory. For each collection it issues
the smallest possible read (query with limit=1) and classifies the result:

    OK       - the read succeeded (scope present)
    MISSING  - HTTP 403 / access-denied (scope not granted)
    AUTH     - HTTP 401 (bad credentials / token)
    ERROR    - any other failure (network, cloud mismatch, etc.)

Collections probed (all READ-only):
    ML Exclusions               -> "Machine Learning Exclusions: Read"
    IOA Exclusions              -> "IOA Exclusions: Read"
    Sensor Visibility Excl.     -> "Sensor Visibility Exclusions: Read"
    Host Groups (optional)      -> "Host Groups: Read"  (only if resolve_group_names)

Exit code 0 = all required scopes present; 1 = at least one required scope
missing/failed. Host Groups is treated as optional (warning only).

Originally proposed by the Copilot coding agent (PR #11); ported here with the
client id masked in output.
"""

from __future__ import annotations

import argparse
import sys
from typing import Optional, Tuple

from .adapters.crowdstrike import CrowdStrikeAdapter, VALID_TYPES
from .config import Config

# Friendly labels for the probe output.
_TYPE_LABEL = {
    "ml": ("ML Exclusions", "Machine Learning Exclusions: Read"),
    "ioa": ("IOA Exclusions", "IOA Exclusions: Read"),
    "sensor_visibility": ("Sensor Visibility Exclusions", "Sensor Visibility Exclusions: Read"),
}

_SYMBOL = {"OK": "[ OK ]", "MISSING": "[FAIL]", "AUTH": "[FAIL]", "ERROR": "[FAIL]"}


def _mask(value: str) -> str:
    """Mask the client id so it isn't fully exposed in shared output/screenshots."""
    return (value[:6] + "...") if value and len(value) > 6 else "****"


def _classify(resp: dict) -> Tuple[str, str]:
    """Map a FalconPy response dict to (state, detail)."""
    status = resp.get("status_code", 0)
    body = resp.get("body", {}) or {}
    errors = body.get("errors") or []
    detail = "; ".join(e.get("message", str(e)) for e in errors) if errors else ""
    if status == 401:
        return "AUTH", detail or "unauthorized"
    if status == 403:
        return "MISSING", detail or "access denied (scope not granted)"
    if status >= 300 or errors:
        return "ERROR", detail or f"HTTP {status}"
    return "OK", ""


def run(config_path: str) -> int:
    cfg = Config.load(config_path)
    if cfg.adapter != "crowdstrike":
        print(f"precheck: adapter is '{cfg.adapter}', not 'crowdstrike' - nothing to check.")
        return 0

    adapter = CrowdStrikeAdapter(cfg.adapter_opts)

    # Resolve base url + credentials up front (clear errors if misconfigured).
    try:
        base_url = adapter._resolve_base_url()
    except ValueError as exc:
        print(f"precheck: {exc}", file=sys.stderr)
        return 1
    try:
        creds = adapter._credentials()
    except ValueError as exc:
        print(f"precheck: {exc}", file=sys.stderr)
        return 1

    types = [t for t in cfg.adapter_opts.get("exclusion_types", list(VALID_TYPES))
             if t in _TYPE_LABEL]
    member_cids = cfg.adapter_opts.get("member_cids") or [None]
    probe_cid: Optional[str] = member_cids[0]

    cloud = cfg.adapter_opts.get("cloud", "us-1")
    print("=" * 70)
    print("  EXCLUSION AUDITOR - CrowdStrike read-scope pre-check (read-only)")
    print(f"  cloud: {cloud}  ({base_url})")
    print(f"  client id: {_mask(creds['client_id'])}")
    if probe_cid:
        print(f"  member_cid: {probe_cid}")
    print("=" * 70)

    try:
        services = adapter._build_services(types, creds, base_url)
    except RuntimeError as exc:
        print(f"precheck: {exc}", file=sys.stderr)
        return 1

    required_ok = True

    for excl_type in types:
        label, scope_name = _TYPE_LABEL[excl_type]
        kwargs = {"limit": 1, "offset": 0}
        if probe_cid:
            kwargs["member_cid"] = probe_cid
        try:
            resp = services[excl_type].query_exclusions(**kwargs)
            state, detail = _classify(resp)
        except Exception as exc:  # network / SDK level
            state, detail = "ERROR", str(exc)
        print(f"  {_SYMBOL[state]}  {label:<32} ({scope_name})")
        if detail:
            print(f"         {detail}")
        if state != "OK":
            required_ok = False

    # Host Groups is optional - only relevant when resolving group names.
    if cfg.adapter_opts.get("resolve_group_names", True):
        try:
            hg = adapter._build_host_group(creds, base_url)
            kwargs = {"limit": 1, "offset": 0}
            if probe_cid:
                kwargs["member_cid"] = probe_cid
            resp = hg.query_host_groups(**kwargs)
            state, detail = _classify(resp)
        except Exception as exc:
            state, detail = "ERROR", str(exc)
        symbol = _SYMBOL[state] if state == "OK" else "[WARN]"
        print(f"  {symbol}  {'Host Groups (optional)':<32} (Host Groups: Read)")
        if detail:
            print(f"         {detail}")
        if state != "OK":
            print("         group IDs will not resolve to names; set "
                  "resolve_group_names: false to silence.")

    print("-" * 70)
    if required_ok:
        print("  RESULT: all required read scopes present. Safe to run the audit.")
    else:
        print("  RESULT: one or more required read scopes are MISSING. Grant the "
              "scopes above\n          to the API client and re-run the pre-check.")
    print("=" * 70)
    return 0 if required_ok else 1


def main(argv: Optional[list] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="exclusion-auditor-precheck",
        description="Read-only check that the Falcon API client has the required exclusion read scopes.",
    )
    parser.add_argument("--config", required=True, help="path to the auditor config.yaml")
    args = parser.parse_args(argv)
    return run(args.config)


if __name__ == "__main__":
    raise SystemExit(main())
