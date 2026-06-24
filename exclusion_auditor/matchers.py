"""Evaluation of a rule's `match` condition tree against one exclusion.

Implements the operators documented in docs/RULE-SCHEMA.md. A condition is a
dict with exactly one key: a combinator (all_of/any_of/not) or a leaf operator.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone

from .datarefs import DataResolver
from .models import NormalizedExclusion
from .paths import (
    base_name,
    file_extension,
    path_is_under,
    wildcard_depth,
)


def _resolve_list(arg, data: DataResolver) -> list:
    """A list argument may be a literal list or a `ref:<name>` string."""
    if isinstance(arg, str) and arg.startswith("ref:"):
        return data.entries(arg[len("ref:"):])
    return list(arg or [])


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_iso(ts: str):
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return None


# --- leaf operators -------------------------------------------------------

def _op_pattern_kind_in(arg, excl, data):
    return excl.pattern_kind in _resolve_list(arg, data)


def _op_extension_in(arg, excl, data):
    ext = file_extension(excl.value)
    if not ext:
        return False
    wanted = [str(e).lower().lstrip(".") for e in _resolve_list(arg, data)]
    return ext in wanted


def _op_value_regex(arg, excl, data):
    return re.search(str(arg), excl.value, re.IGNORECASE) is not None


def _op_path_under(arg, excl, data):
    bases = _resolve_list(arg, data)
    return any(path_is_under(excl.value, b) for b in bases)


def _op_wildcard_at_depth_lte(arg, excl, data):
    depth = wildcard_depth(excl.value)
    return depth != -1 and depth <= int(arg)


def _op_process_name_in(arg, excl, data):
    names = [str(n).lower() for n in _resolve_list(arg, data)]
    return base_name(excl.value) in names


def _op_overlaps_known_path(arg, excl, data):
    ref = arg[len("ref:"):] if isinstance(arg, str) and arg.startswith("ref:") else "lolbins"
    bins = data.lolbins(ref)
    if base_name(excl.value) in bins["binaries"]:
        return True
    for d in bins["directories"]:
        # exclusion sits inside a sensitive dir, OR sits above one (contains it)
        if path_is_under(excl.value, d) or path_is_under(d, excl.value):
            return True
    return False


def _op_scope_equals(arg, excl, data):
    return excl.scope == str(arg)


def _op_field_empty(arg, excl, data):
    return not str(getattr(excl, str(arg), "") or "").strip()


def _op_age_days_gte(arg, excl, data):
    created = _parse_iso(excl.created_at)
    if created is None:
        return False
    return (_now() - created).days >= int(arg)


LEAF_OPS = {
    "pattern_kind_in": _op_pattern_kind_in,
    "extension_in": _op_extension_in,
    "value_regex": _op_value_regex,
    "path_under": _op_path_under,
    "wildcard_at_depth_lte": _op_wildcard_at_depth_lte,
    "process_name_in": _op_process_name_in,
    "overlaps_known_path": _op_overlaps_known_path,
    "scope_equals": _op_scope_equals,
    "field_empty": _op_field_empty,
    "age_days_gte": _op_age_days_gte,
}


def evaluate(condition: dict, excl: NormalizedExclusion, data: DataResolver) -> bool:
    if not isinstance(condition, dict) or len(condition) != 1:
        raise ValueError(f"match condition must be a single-key mapping, got: {condition!r}")
    key, arg = next(iter(condition.items()))

    if key == "all_of":
        return all(evaluate(c, excl, data) for c in arg)
    if key == "any_of":
        return any(evaluate(c, excl, data) for c in arg)
    if key == "not":
        return not evaluate(arg, excl, data)

    op = LEAF_OPS.get(key)
    if op is None:
        raise ValueError(f"unknown match operator: {key!r}")
    return op(arg, excl, data)
