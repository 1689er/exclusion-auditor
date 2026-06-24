"""Import adapter: read already-exported exclusions from JSON or CSV.

This is the vendor-agnostic, credential-free entry point. Any platform can
export exclusions, map them into the normalized fields, and audit them — and
it's how the bundled demo runs with zero setup.
"""

from __future__ import annotations

import csv
import json
import os
from typing import List

from ..models import NormalizedExclusion
from .base import Adapter


class ImportAdapter(Adapter):
    def fetch(self) -> List[NormalizedExclusion]:
        path = self.opts.get("path")
        if not path:
            raise ValueError("import adapter requires 'path' in config")
        if not os.path.isfile(path):
            raise FileNotFoundError(f"import file not found: {path}")

        ext = os.path.splitext(path)[1].lower()
        if ext == ".json":
            rows = self._read_json(path)
        elif ext == ".csv":
            rows = self._read_csv(path)
        else:
            raise ValueError(f"unsupported import format '{ext}' (use .json or .csv)")
        return [NormalizedExclusion.from_dict(r) for r in rows]

    @staticmethod
    def _read_json(path: str) -> List[dict]:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if isinstance(data, dict) and "exclusions" in data:
            data = data["exclusions"]
        if not isinstance(data, list):
            raise ValueError("JSON import must be a list (or {'exclusions': [...]})")
        return data

    @staticmethod
    def _read_csv(path: str) -> List[dict]:
        with open(path, "r", encoding="utf-8", newline="") as fh:
            return list(csv.DictReader(fh))
