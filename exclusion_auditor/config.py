"""Configuration loading. Everything environment-specific lives here so users
configure the tool to their environment without touching code."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List

import yaml


@dataclass
class Config:
    adapter: str = "import"
    adapter_opts: Dict = field(default_factory=dict)
    rules_paths: List[str] = field(default_factory=lambda: ["rules"])
    data_dir: str = "data"
    data_overrides: Dict[str, str] = field(default_factory=dict)
    suppressions_path: str = ""
    output_format: str = "table"
    min_severity: str = "info"
    ci_fail_on: str = "critical"

    @classmethod
    def load(cls, path: str) -> "Config":
        with open(path, "r", encoding="utf-8") as fh:
            raw = yaml.safe_load(fh) or {}
        adapter = raw.get("adapter", "import")
        rules = raw.get("rules", {}) or {}
        output = raw.get("output", {}) or {}
        ci = raw.get("ci", {}) or {}
        return cls(
            adapter=adapter,
            # the adapter's own block, e.g. raw["crowdstrike"] or raw["import"]
            adapter_opts=raw.get(adapter, {}) or {},
            rules_paths=list(rules.get("paths", ["rules"])),
            data_dir=raw.get("data_dir", "data"),
            data_overrides=raw.get("data_overrides", {}) or {},
            suppressions_path=raw.get("suppressions", ""),
            output_format=output.get("format", "table"),
            min_severity=output.get("min_severity", "info"),
            ci_fail_on=ci.get("fail_on", "critical"),
        )
