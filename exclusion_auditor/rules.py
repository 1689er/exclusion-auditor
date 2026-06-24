"""Loading and representing risk rules."""

from __future__ import annotations

import glob
import os
from dataclasses import dataclass, field
from typing import List

import yaml


@dataclass
class Rule:
    id: str
    name: str
    severity: str
    category: str
    applies_to_types: List[str]
    match: dict
    description: str = ""
    rationale: str = ""
    remediation: str = ""
    mitre: str = ""
    references: List[str] = field(default_factory=list)
    enabled: bool = True
    requires: str = ""          # "" | "metadata" | "corpus"
    escalates: bool = False
    source_file: str = ""

    def applies_to(self, excl_type: str) -> bool:
        return "*" in self.applies_to_types or excl_type in self.applies_to_types

    @classmethod
    def from_dict(cls, d: dict, source_file: str = "") -> "Rule":
        return cls(
            id=d["id"],
            name=d.get("name", d["id"]),
            severity=d.get("severity", "medium"),
            category=d.get("category", "uncategorized"),
            applies_to_types=list(d.get("applies_to_types", ["*"])),
            match=d.get("match", {}),
            description=d.get("description", ""),
            rationale=d.get("rationale", ""),
            remediation=d.get("remediation", ""),
            mitre=d.get("mitre", ""),
            references=list(d.get("references", [])),
            enabled=bool(d.get("enabled", True)),
            requires=d.get("requires", ""),
            escalates=bool(d.get("escalates", False)),
            source_file=source_file,
        )


def load_rules(paths: List[str]) -> List[Rule]:
    """Load every rule from the given files/directories.

    Later definitions of the same rule id override earlier ones, so a user's
    custom rules directory (listed after the bundled `rules/`) can shadow a
    bundled rule by reusing its id.
    """
    files: List[str] = []
    for p in paths:
        if os.path.isdir(p):
            files.extend(sorted(glob.glob(os.path.join(p, "**", "*.yml"), recursive=True)))
            files.extend(sorted(glob.glob(os.path.join(p, "**", "*.yaml"), recursive=True)))
        elif os.path.isfile(p):
            files.append(p)

    by_id = {}
    for f in files:
        with open(f, "r", encoding="utf-8") as fh:
            doc = yaml.safe_load(fh) or []
        items = doc if isinstance(doc, list) else [doc]
        for item in items:
            if not isinstance(item, dict) or "id" not in item:
                continue
            rule = Rule.from_dict(item, source_file=f)
            by_id[rule.id] = rule
    return list(by_id.values())
