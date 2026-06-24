"""Resolves `ref:<name>` data lists used by rules (writable paths, interpreters,
LOLBins). Keeping these out of the rules lets users extend them per environment
without editing rule logic."""

from __future__ import annotations

import os
from typing import Dict

import yaml

# ref name -> default file (relative to the configured data dir)
DEFAULT_FILES = {
    "writable-paths": "writable-paths.yml",
    "interpreters": "interpreters.yml",
    "lolbins": "lolbins.yml",
}


class DataResolver:
    def __init__(self, data_dir: str = "data", overrides: Dict[str, str] | None = None):
        self.data_dir = data_dir
        self.overrides = overrides or {}
        self._cache: Dict[str, object] = {}

    def _path_for(self, ref: str) -> str:
        if ref in self.overrides:
            return self.overrides[ref]
        if ref in DEFAULT_FILES:
            return os.path.join(self.data_dir, DEFAULT_FILES[ref])
        # allow refs that are just a filename living in the data dir
        return os.path.join(self.data_dir, ref if ref.endswith((".yml", ".yaml")) else ref + ".yml")

    def load(self, ref: str) -> object:
        if ref in self._cache:
            return self._cache[ref]
        path = self._path_for(ref)
        with open(path, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
        self._cache[ref] = data
        return data

    def entries(self, ref: str) -> list:
        """List-style data files expose their items under `entries:`."""
        data = self.load(ref)
        if isinstance(data, dict):
            return list(data.get("entries", []))
        if isinstance(data, list):
            return data
        return []

    def lolbins(self, ref: str = "lolbins") -> dict:
        data = self.load(ref)
        if not isinstance(data, dict):
            return {"directories": [], "binaries": []}
        return {
            "directories": data.get("directories", []),
            "binaries": [str(b).lower() for b in data.get("binaries", [])],
        }
