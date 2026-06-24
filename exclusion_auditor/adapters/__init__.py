"""Adapters pull exclusions from a source and normalize them.

Register new adapters (e.g. crowdstrike) in ADAPTERS so the CLI can select them
by name from config.
"""

from __future__ import annotations

from typing import Callable, Dict

from .crowdstrike import CrowdStrikeAdapter
from .import_adapter import ImportAdapter

# name -> factory(adapter_opts) -> adapter instance with .fetch()
ADAPTERS: Dict[str, Callable] = {
    "import": ImportAdapter,
    "crowdstrike": CrowdStrikeAdapter,
}


def get_adapter(name: str, opts: dict):
    if name not in ADAPTERS:
        raise ValueError(
            f"unknown adapter '{name}'. available: {', '.join(sorted(ADAPTERS))}"
        )
    return ADAPTERS[name](opts)
