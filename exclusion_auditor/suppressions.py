"""Suppression handling. A suppression silences a reviewed-and-accepted finding,
but the finding is still reported (never silently dropped) so it can be re-reviewed."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import date
from typing import List, Optional

import yaml


@dataclass
class Suppression:
    rule_id: str
    reason: str
    value: str = ""
    value_regex: str = ""
    expires: str = ""

    def is_expired(self, today: Optional[date] = None) -> bool:
        if not self.expires:
            return False
        today = today or date.today()
        try:
            return date.fromisoformat(str(self.expires)) < today
        except ValueError:
            return False

    def matches(self, rule_id: str, exclusion_value: str) -> bool:
        if self.rule_id != rule_id or self.is_expired():
            return False
        if self.value:
            return self.value == exclusion_value
        if self.value_regex:
            return re.search(self.value_regex, exclusion_value) is not None
        return True  # rule-wide suppression


def load_suppressions(path: str) -> List[Suppression]:
    if not path:
        return []
    with open(path, "r", encoding="utf-8") as fh:
        raw = yaml.safe_load(fh) or {}
    out = []
    for item in raw.get("suppressions", []) or []:
        out.append(
            Suppression(
                rule_id=item.get("rule_id", ""),
                reason=item.get("reason", ""),
                value=item.get("value", ""),
                value_regex=item.get("value_regex", ""),
                expires=item.get("expires", ""),
            )
        )
    return out
