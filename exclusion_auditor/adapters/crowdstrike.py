"""CrowdStrike Falcon adapter (READ-ONLY).

Pulls the three exclusion collections via FalconPy and normalizes them:
  - ML Exclusions            -> type "ml"           (path/glob values)
  - Sensor Visibility Excl.  -> type "sensor_visibility"
  - IOA Exclusions           -> type "ioa"          (behavioral; ifn_regex/cl_regex)

Design notes:
  * Read-only: only query_exclusions / get_exclusions are ever called.
  * Credentials come from environment variables named in config; secrets are
    never read from the config file itself.
  * The normalization functions and pagination helper are pure and take plain
    dicts / duck-typed service objects, so they unit-test with no falconpy and
    no live tenant.
"""

from __future__ import annotations

import os
import re
import sys
from typing import Callable, Dict, List, Optional

from ..models import NormalizedExclusion
from .base import Adapter

# Falcon cloud region -> API base URL.
CLOUD_URLS = {
    "us-1": "https://api.crowdstrike.com",
    "us-2": "https://api.us-2.crowdstrike.com",
    "eu-1": "https://api.eu-1.crowdstrike.com",
    "us-gov-1": "https://api.laggar.gcw.crowdstrike.com",
    "us-gov-2": "https://api.us-gov-2.crowdstrike.com",
}

VALID_TYPES = ("ml", "sensor_visibility", "ioa")
_WILDCARD = ("*", "?")


def ioa_regex_to_path(regex: str) -> str:
    """Convert a Falcon IOA image-filename REGEX into a comparable glob path.

    IOA exclusions store the excluded image as a regex (e.g.
    ``.*\\\\powershell\\.exe``), not a path. Left raw, the process matchers see
    a base name of ``.exe`` and a pattern_kind that never reflects the regex, so
    EXCL-PROC-001/002 can never fire on IOA exclusions. This maps the regex back
    to a path-shaped value: unescape ``\\.`` and ``\\\\``, turn a leading ``.*``
    (any-path prefix) into ``**`` so path_is_under can anchor it, and turn any
    remaining ``.*`` / ``.+`` into ``*``. Alternation groups ``(a|b)`` are left
    intact (they still read as a wildcard segment).
    """
    s = (regex or "").strip()
    if s.startswith("^"):
        s = s[1:]
    if s.endswith("$"):
        s = s[:-1]
    s = s.replace("\\\\", "\x00")   # protect literal backslash
    s = s.replace("\\.", ".")        # unescape dot
    s = re.sub(r"^\.\*", "**", s)     # leading any-path prefix -> **
    s = s.replace(".*", "*").replace(".+", "*")
    s = s.replace("\x00", "\\")
    return s


def ioa_pattern_kind(value: str) -> str:
    """process when the (normalized) IOA value is a concrete image path;
    wildcard when it still carries glob/alternation that an attacker could satisfy."""
    return "wildcard" if any(c in value for c in ("*", "?", "(", "|")) else "process"


# --- pure normalization ---------------------------------------------------

def infer_pattern_kind(value: str) -> str:
    v = value or ""
    if any(c in v for c in _WILDCARD):
        return "wildcard"
    if ("\\" in v) or ("/" in v):
        return "path"
    # No path separator and no wildcard: a bare name/extension token. Treated as
    # "extension" so it stays consistent with paths.file_extension().
    return "extension"


def _scope(raw: dict, group_names: Optional[Dict[str, str]] = None) -> str:
    if raw.get("applied_globally"):
        return "global"
    group_names = group_names or {}
    names = []
    for g in raw.get("groups") or []:
        if isinstance(g, dict):
            # dict may already carry the name; otherwise fall back to the id map
            names.append(g.get("name") or group_names.get(g.get("id", ""), g.get("id", "")))
        else:
            names.append(group_names.get(g, g))  # g is a bare id string
    names = [n for n in names if n]
    return "host_group:" + (",".join(names) if names else "scoped")


def normalize_ml(raw: dict, tenant_cid: str = "",
                 group_names: Optional[Dict[str, str]] = None) -> NormalizedExclusion:
    value = raw.get("value", "") or ""
    return NormalizedExclusion(
        id=str(raw.get("id", "")),
        platform="crowdstrike",
        type="ml",
        value=value,
        pattern_kind=infer_pattern_kind(value),
        scope=_scope(raw, group_names),
        tenant_cid=tenant_cid,
        created_by=raw.get("created_by", "") or "",
        created_at=raw.get("created_on", "") or raw.get("modified_on", "") or "",
        comment=raw.get("comment", "") or "",
    )


def normalize_sensor_visibility(raw: dict, tenant_cid: str = "",
                                group_names: Optional[Dict[str, str]] = None) -> NormalizedExclusion:
    value = raw.get("value", "") or ""
    return NormalizedExclusion(
        id=str(raw.get("id", "")),
        platform="crowdstrike",
        type="sensor_visibility",
        value=value,
        pattern_kind=infer_pattern_kind(value),
        scope=_scope(raw, group_names),
        tenant_cid=tenant_cid,
        created_by=raw.get("created_by", "") or "",
        created_at=raw.get("created_on", "") or raw.get("last_modified", "") or "",
        comment=raw.get("comment", "") or "",
    )


def normalize_ioa(raw: dict, tenant_cid: str = "",
                  group_names: Optional[Dict[str, str]] = None) -> NormalizedExclusion:
    # IOA exclusions are behavioral; normalize the image-file-name regex to a
    # comparable path so the process matchers (EXCL-PROC-001/002) can evaluate it.
    raw_value = raw.get("ifn_regex") or raw.get("value", "") or ""
    value = ioa_regex_to_path(raw_value)
    # Map ONLY the admin-provided description to comment so `has_comment` is honest
    # (issue #6). Falcon IOA uses "description"; fall back to "comment".
    comment = raw.get("description") or raw.get("comment") or ""
    return NormalizedExclusion(
        id=str(raw.get("id", "")),
        platform="crowdstrike",
        type="ioa",
        value=value,
        pattern_kind=ioa_pattern_kind(value),
        scope=_scope(raw, group_names),
        tenant_cid=tenant_cid,
        created_by=raw.get("created_by", "") or "",
        created_at=raw.get("created_on", "") or "",
        comment=comment,
    )


NORMALIZERS: Dict[str, Callable[..., NormalizedExclusion]] = {
    "ml": normalize_ml,
    "sensor_visibility": normalize_sensor_visibility,
    "ioa": normalize_ioa,
}


# --- read-only pagination -------------------------------------------------

def _check(resp: dict, op: str) -> dict:
    """Validate a FalconPy response and return its body, or raise on API error."""
    status = resp.get("status_code", 0)
    body = resp.get("body", {}) or {}
    if status >= 300 or (body.get("errors")):
        errors = body.get("errors") or [{"message": f"HTTP {status}"}]
        msg = "; ".join(e.get("message", str(e)) for e in errors)
        raise RuntimeError(f"Falcon API error during {op}: {msg}")
    return body


def _chunks(seq: List, size: int):
    for i in range(0, len(seq), size):
        yield seq[i:i + size]


def collect_all(service, member_cid: Optional[str] = None,
                page_size: int = 500, detail_batch: int = 100) -> List[dict]:
    """Page through query_exclusions to gather ids, then get_exclusions for
    details. `service` only needs query_exclusions/get_exclusions methods, so a
    fake can be injected in tests."""
    ids: List[str] = []
    offset = 0
    while True:
        kwargs = {"limit": page_size, "offset": offset}
        if member_cid:
            kwargs["member_cid"] = member_cid
        body = _check(service.query_exclusions(**kwargs), "query_exclusions")
        batch = body.get("resources", []) or []
        ids.extend(batch)
        total = ((body.get("meta", {}) or {}).get("pagination", {}) or {}).get("total", len(ids))
        offset += len(batch)
        if not batch or offset >= total:
            break

    resources: List[dict] = []
    for chunk in _chunks(ids, detail_batch):
        kwargs = {"ids": chunk}
        if member_cid:
            kwargs["member_cid"] = member_cid
        body = _check(service.get_exclusions(**kwargs), "get_exclusions")
        resources.extend(body.get("resources", []) or [])
    return resources


# --- host group name resolution -------------------------------------------

def group_ids_by_cid(collected: List[tuple]) -> Dict[Optional[str], set]:
    """From a list of (type, cid, raw) tuples, collect the referenced host group
    ids grouped by member CID (group ids are scoped to their CID)."""
    by_cid: Dict[Optional[str], set] = {}
    for _excl_type, cid, raw in collected:
        for g in raw.get("groups") or []:
            gid = g.get("id") if isinstance(g, dict) else g
            if gid:
                by_cid.setdefault(cid, set()).add(gid)
    return by_cid


def resolve_group_names(hg_service, ids_by_cid: Dict[Optional[str], set],
                        detail_batch: int = 100) -> Dict[str, str]:
    """Build an id -> name map. `hg_service` only needs get_host_groups, so a
    fake can be injected in tests."""
    mapping: Dict[str, str] = {}
    for cid, ids in ids_by_cid.items():
        for chunk in _chunks(list(ids), detail_batch):
            kwargs = {"ids": chunk}
            if cid:
                kwargs["member_cid"] = cid
            body = _check(hg_service.get_host_groups(**kwargs), "get_host_groups")
            for r in body.get("resources", []) or []:
                if r.get("id"):
                    mapping[r["id"]] = r.get("name", r["id"])
    return mapping


# --- adapter --------------------------------------------------------------

class CrowdStrikeAdapter(Adapter):
    def _resolve_base_url(self) -> str:
        if self.opts.get("base_url"):
            return self.opts["base_url"]
        cloud = self.opts.get("cloud", "us-1")
        if cloud not in CLOUD_URLS:
            raise ValueError(
                f"unknown cloud '{cloud}'. known: {', '.join(CLOUD_URLS)} "
                "(or set base_url explicitly)"
            )
        return CLOUD_URLS[cloud]

    def _credentials(self) -> Dict[str, str]:
        id_env = self.opts.get("client_id_env", "FALCON_CLIENT_ID")
        secret_env = self.opts.get("client_secret_env", "FALCON_CLIENT_SECRET")
        client_id = os.environ.get(id_env)
        client_secret = os.environ.get(secret_env)
        if not client_id or not client_secret:
            raise ValueError(
                f"missing Falcon credentials: set env vars {id_env} and {secret_env} "
                "(API client needs READ scope on the exclusion collections)"
            )
        return {"client_id": client_id, "client_secret": client_secret}

    def _build_services(self, types: List[str], creds: Dict[str, str], base_url: str) -> Dict:
        try:
            from falconpy import IOAExclusions, MLExclusions, SensorVisibilityExclusions
        except ImportError as exc:
            raise RuntimeError(
                "CrowdStrike adapter requires falconpy. Install with: "
                "pip install crowdstrike-falconpy   (or: pip install '.[crowdstrike]')"
            ) from exc
        classes = {
            "ml": MLExclusions,
            "ioa": IOAExclusions,
            "sensor_visibility": SensorVisibilityExclusions,
        }
        return {t: classes[t](base_url=base_url, **creds) for t in types}

    def _build_host_group(self, creds: Dict[str, str], base_url: str):
        from falconpy import HostGroup
        return HostGroup(base_url=base_url, **creds)

    def fetch(self) -> List[NormalizedExclusion]:
        types = self.opts.get("exclusion_types", list(VALID_TYPES))
        bad = [t for t in types if t not in VALID_TYPES]
        if bad:
            raise ValueError(f"invalid exclusion_types {bad}; valid: {list(VALID_TYPES)}")

        base_url = self._resolve_base_url()
        creds = self._credentials()
        services = self._build_services(types, creds, base_url)
        member_cids = self.opts.get("member_cids") or [None]

        # 1. gather raw exclusions (keep type + cid alongside each)
        collected: List[tuple] = []
        for excl_type, service in services.items():
            for cid in member_cids:
                for raw in collect_all(service, member_cid=cid):
                    collected.append((excl_type, cid, raw))

        # 2. resolve host group names (best-effort; degrade to ids on error)
        group_names: Dict[str, str] = {}
        if self.opts.get("resolve_group_names", True):
            ids_by_cid = group_ids_by_cid(collected)
            if ids_by_cid:
                try:
                    hg = self._build_host_group(creds, base_url)
                    group_names = resolve_group_names(hg, ids_by_cid)
                except Exception as exc:  # missing scope, API error, etc.
                    print(f"warning: could not resolve host group names ({exc}); "
                          "showing group IDs. Grant 'Host Groups: Read' or set "
                          "resolve_group_names: false to silence.", file=sys.stderr)

        # 3. normalize
        return [
            NORMALIZERS[excl_type](raw, cid or "", group_names)
            for excl_type, cid, raw in collected
        ]
