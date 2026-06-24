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


def path_is_under(value: str, base: str) -> bool:
    """True when `value` is at or below `base` (base treated as a path pattern)."""
    v = normalize_segments(value)
    b = normalize_segments(base)
    # A trailing "*" on the base is a subtree marker ("everything below"); drop it.
    while b and b[-1] in WILDCARD_CHARS:
        b.pop()
    if not b or len(v) < len(b):
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
