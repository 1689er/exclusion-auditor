"""Command-line entry point: exclusion-auditor --config config.yaml"""

from __future__ import annotations

import argparse
import json
import sys
from typing import List

from . import __version__, report
from .adapters import get_adapter
from .config import Config
from .datarefs import DataResolver
from .engine import Engine
from .models import Finding, severity_rank
from .rules import load_rules
from .suppressions import load_suppressions


def _filter_min_severity(findings: List[Finding], min_sev: str) -> List[Finding]:
    """Drop non-suppressed findings below the threshold; always keep suppressed
    ones so they remain visible for re-review."""
    floor = severity_rank(min_sev)
    return [f for f in findings if f.suppressed or severity_rank(f.severity) >= floor]


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="exclusion-auditor",
        description="Read-only NGAV/EDR exclusion risk and hygiene auditor.",
    )
    p.add_argument("-c", "--config", help="path to config YAML (required unless --verify-share)")
    p.add_argument("--format", choices=["table", "json", "markdown"],
                   help="override output format")
    p.add_argument("--min-severity", choices=["info", "low", "medium", "high", "critical"],
                   help="override minimum severity to report")
    p.add_argument("--ci", action="store_true",
                   help="exit non-zero if any finding is at/above the ci.fail_on severity")
    p.add_argument("--redact", action="store_true",
                   help="sanitize output for safe sharing (no values, paths, identities, or tenant IDs)")
    p.add_argument("--share-out", metavar="PATH",
                   help="write a sanitized JSON report to PATH (safe to share externally)")
    p.add_argument("--summary-only", action="store_true",
                   help="sanitized output with only the aggregate summary (no per-finding rows)")
    p.add_argument("--salt-file", metavar="PATH",
                   help="use a persistent salt from PATH for value tokens (stable across runs); created if missing")
    p.add_argument("--verify-share", metavar="PATH",
                   help="scan a file for likely-sensitive content, report whether it's safe to share, and exit")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def _decode_best(raw: bytes) -> str:
    """Decode bytes robustly. Windows tools (PowerShell `>`/Out-File) often emit
    UTF-16, so try common encodings before a lossless latin-1 fallback. Reading the
    wrong encoding could otherwise hide sensitive content from the scanner."""
    for enc in ("utf-8-sig", "utf-16", "utf-8"):
        try:
            return raw.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    return raw.decode("latin-1", errors="replace")


def _verify_share(path: str) -> int:
    """Scan a file for sensitive content before it's shared (issues #2/#7)."""
    from .redact import scan_for_sensitive
    try:
        with open(path, "rb") as fh:
            text = _decode_best(fh.read())
    except OSError as exc:
        print(f"error: cannot read {path}: {exc}", file=sys.stderr)
        return 2
    hits = scan_for_sensitive(text)
    if not hits:
        print(f"SAFE: no obvious sensitive content found in {path}.")
        print("(Heuristic check - still confirm it was produced with --share-out/--redact.)")
        return 0
    print(f"UNSAFE: {path} appears to contain sensitive content - do NOT share:",
          file=sys.stderr)
    for name, sample in hits:
        print(f"  - {name}: {sample}", file=sys.stderr)
    print("This looks like a full/confidential report. Regenerate with --share-out.",
          file=sys.stderr)
    return 1


def main(argv=None) -> int:
    # Make output robust on Windows code pages and when redirected to a file.
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass

    args = build_parser().parse_args(argv)

    # --verify-share is a standalone utility; it needs no config or tenant.
    if args.verify_share:
        return _verify_share(args.verify_share)

    if not args.config:
        print("error: --config is required (unless using --verify-share)", file=sys.stderr)
        return 2
    cfg = Config.load(args.config)

    fmt = args.format or cfg.output_format
    min_sev = args.min_severity or cfg.min_severity

    # 1. fetch (read-only) and normalize
    try:
        adapter = get_adapter(cfg.adapter, cfg.adapter_opts)
        exclusions = adapter.fetch()
    except Exception as exc:  # surface a clean message, not a traceback
        print(f"error: failed to load exclusions via '{cfg.adapter}' adapter: {exc}",
              file=sys.stderr)
        return 2

    # 2. load rules, data, suppressions
    rules = load_rules(cfg.rules_paths)
    if not rules:
        print(f"error: no rules found in {cfg.rules_paths}", file=sys.stderr)
        return 2
    data = DataResolver(cfg.data_dir, cfg.data_overrides)
    suppressions = load_suppressions(cfg.suppressions_path)

    # 3. audit
    findings = Engine(rules, data, suppressions).run(exclusions)
    findings = _filter_min_severity(findings, min_sev)

    # 4. report
    total = len(exclusions)
    want_sanitized = args.redact or args.share_out or args.summary_only
    share = None
    if want_sanitized:
        from .redact import build_share_report, load_or_create_salt
        salt = load_or_create_salt(args.salt_file) if args.salt_file else None
        share = build_share_report(findings, total, salt=salt)
        if args.summary_only:
            share = {k: v for k, v in share.items() if k != "findings"}
            share["findings"] = []

    if args.share_out:
        try:
            with open(args.share_out, "w", encoding="utf-8") as fh:
                json.dump(share, fh, indent=2)
            print(f"wrote sanitized report to {args.share_out}", file=sys.stderr)
        except OSError as exc:
            print(f"error: could not write sanitized report: {exc}", file=sys.stderr)
            return 2

    if args.redact or args.summary_only:
        print(report.render_sanitized(share, fmt))
    else:
        print(report.render(findings, fmt, total_exclusions=total))

    # 5. CI gate
    if args.ci:
        worst = report.max_severity(findings)
        if severity_rank(worst) >= severity_rank(cfg.ci_fail_on):
            print(f"\nCI gate: worst finding '{worst}' >= fail_on '{cfg.ci_fail_on}' -> failing.",
                  file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
