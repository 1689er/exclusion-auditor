"""Adapter interface. Every adapter is READ-ONLY: it may only fetch exclusions,
never create, modify, or delete them. This is a hard project rule."""

from __future__ import annotations

from typing import List

from ..models import NormalizedExclusion


class Adapter:
    def __init__(self, opts: dict):
        self.opts = opts or {}

    def fetch(self) -> List[NormalizedExclusion]:
        raise NotImplementedError
