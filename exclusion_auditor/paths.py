"""Path normalization helpers shared by the path-aware matchers.

Exclusion values come in many shapes (env vars, per-user wildcards, mixed
separators, trailing subtree markers). Everything funnels through here so the
matchers can reason about paths consistently and cross-platform.
"""

from __future__ import annotations

from typing import List

# Common Windows environment variables expanded to a canonical, comparable form.
# The username segment becomes "*" so per-user paths compare structurally.
ENV_MAP = {
    "%temp%": r"c:\users\*\appdata\local\temp",
    "%tmp%": r"c:\users\*\appdata\local\temp",
    "%appdata%": r"c:\users\*\appdata\roaming",
    "%localappdata%": r"c:\users\*\appdata\local",
    "%public%": r"c:\users\public",
    "%userprofile%": r"c:\users\*",
    "%programdata%": r"c:\programdata",
    "%programfiles%": r"c:\program files",
    "%programfiles(x86)%": r"c:\program files (x86)",
    "%systemroot%": r"c:\windows",
    "%windir%": r"c:\windows",
    "%systemdrive%": r"c:",
}

WILDCARD_CHARS = ("*", "?")


def normalize_segments(path: str, expand_env: bool = True) -> List[str]:
    """Lowercase, expand env vars, unify separators, split into segments."""
    p = (path or "").strip().lower()
    if expand_env:
        for k, v in ENV_MAP.items():
            p = p.replace(k, v)
    p = p.replace("/", "\\")
    return [seg for seg in p.split("\\") if seg != ""]


def _seg_match(base_seg: str, value_seg: str) -> bool:
    """Asymmetric: a wildcard in the *base* (pattern) matches any value segment,
    but a wildcard in the value must equal the base literally. This prevents a
    value like C:\\users\\*\\... from being judged 'under' C:\\users\\public."""
    return base_seg == "*" or base_seg == value_seg


def _strip_any_volume_prefix(segs: List[str]) -> tuple:
    """Strip a CrowdStrike-style 'any volume / any path' prefix from a value's
    segments. Falcon exclusions are commonly written as ``**\\...`` ("match on
    any volume / any leading path") or as an NT object path
    ``\\Device\\HarddiskVolume3\\...``. Both mean "the drive/leading path is
    unspecified", so for containment checks the remainder should be matched
    against a base regardless of drive. Returns (segments, had_prefix)."""
    if segs and segs[0] == "**":
        return segs[1:], True
    if len(segs) >= 2 and segs[0] == "device" and segs[1].startswith("harddiskvolume"):
        return segs[2:], True
    return segs, False


def path_is_under(value: str, base: str) -> bool:
    """True when `value` is at or below `base` (base treated as a path pattern).

    Handles CrowdStrike's any-volume value prefixes (``**\\...`` and
    ``\\Device\\HarddiskVolume*\\...``): when present, the base may match
    starting anywhere in the remaining value segments and a leading drive
    segment on the base (e.g. ``c:``) is dropped, since the value's volume is
    unspecified. Without such a prefix the original drive-anchored behavior is
    preserved exactly."""
    v = normalize_segments(value)
    b = normalize_segments(base)
    # A trailing "*" on the base is a subtree marker ("everything below"); drop it.
    while b and b[-1] in WILDCARD_CHARS:
        b.pop()
    if not b:
        return False

    v, any_volume = _strip_any_volume_prefix(v)
    if any_volume:
        # The value's volume/leading path is unspecified. Drop a leading drive
        # segment on the base so the concrete tail can align...
        if b and b[0].endswith(":"):
            b = b[1:]
        if not b or not v or len(v) < len(b):
            return False
        # ...and allow the base to match starting anywhere in the remainder.
        for start in range(0, len(v) - len(b) + 1):
            if all(_seg_match(b[i], v[start + i]) for i in range(len(b))):
                return True
        return False

    if len(v) < len(b):
        return False
    return all(_seg_match(b[i], v[i]) for i in range(len(b)))


def is_path_like(value: str) -> bool:
    """Does the value look like a filesystem path (vs. a bare extension/name)?"""
    return ("\\" in value) or ("/" in value)


def file_extension(value: str) -> str:
    """Extension (lowercased, no dot) only when the value is a bare extension
    pattern such as '*.ps1', '.ps1', or 'ps1' — not a full path ending in .ps1."""
    if is_path_like(value):
        return ""
    name = value.strip().lower().lstrip("*")
    if "." in name:
        return name.rsplit(".", 1)[-1]
    # bare token like "ps1"
    return name if name.isalnum() else ""


def base_name(value: str) -> str:
    """Final path segment (the file/process name), lowercased."""
    segs = normalize_segments(value, expand_env=False)
    return segs[-1] if segs else value.strip().lower()


def wildcard_depth(value: str) -> int:
    """Segment depth (drive = 0) of the first wildcard, or -1 if none.

    Uses the raw value so env-var expansion can't introduce phantom wildcards.

    A leading any-volume prefix is skipped before measuring depth: CrowdStrike
    writes exclusions as ``**\\...`` ("any volume / any leading path") or as an
    NT object path ``\\Device\\HarddiskVolume*\\...``. That prefix is an
    addressing convention, NOT a root-level wildcard, so a specific target like
    ``**\\Vendor\\app.exe`` must not be scored as a near-root (depth<=1)
    exclusion. Genuinely broad shapes keep an early wildcard after the prefix
    (e.g. ``\\Device\\HarddiskVolume*\\Users\\*\\...\\**\\*`` -> depth 1).
    """
    segs = normalize_segments(value, expand_env=False)
    if segs and segs[0] == "**":
        segs = segs[1:]
    elif len(segs) >= 2 and segs[0] == "device" and segs[1].startswith("harddiskvolume"):
        segs = segs[2:]
    for idx, seg in enumerate(segs):
        if any(c in seg for c in WILDCARD_CHARS):
            return idx
    return -1
