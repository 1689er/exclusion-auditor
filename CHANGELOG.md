# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-06-24
First public release.

### Added
- Vendor-agnostic risk engine for EDR/NGAV exclusions: a YAML rule library
  (extension, path, process, scope, and hygiene rules), data-driven `ref:` lists
  (writable paths, interpreters, LOLBins), scope-based escalation, and suppressions.
- **CrowdStrike Falcon adapter** (read-only): ML, IOA, and Sensor Visibility
  exclusions via FalconPy, with pagination and host-group name resolution.
- **Import adapter**: audit exclusions exported to JSON or CSV — any vendor, no credentials.
- CLI with `table` / `json` / `markdown` output, a `--ci` gate, and `--check-scopes`
  read-only scope pre-flight.
- Report separates **Risk findings** (critical/high/medium) from a compact **Hygiene**
  section so low-severity governance noise never buries real findings.
- **Enterprise-safe sharing**: `--redact`, `--share-out` (auto-verified), `--summary-only`,
  `--salt-file`, and `--verify-share` (encoding-aware). Sanitized output strips exclusion
  values, paths, admin identities, comments, host-group names, and tenant IDs, replacing
  each value with a per-run hashed token so correlation survives but values can't be recovered.
- Confidential-output guards (`.gitignore` patterns; full reports labelled CONFIDENTIAL).
- Documentation: rule schema, configuration, adapters, enterprise/data-handling, and
  safe-sharing guides.
- Community: GitHub Discussions plus issue/PR templates that request sanitized reports only.
- Test suite (engine + CrowdStrike normalization; no credentials needed), CI across
  Python 3.9–3.12, and a CodeQL workflow.

### Security
- Read-only by design — adapters only ever read exclusions; credentials come from the
  environment and are never written to disk.
- GitHub Actions pinned to commit SHAs; CodeQL static analysis on every commit.

### Calibration
Validated against a real production CrowdStrike tenant, which surfaced and fixed real
matcher gaps:
- `path_is_under` now handles CrowdStrike any-volume value prefixes (`**\…` and
  `\Device\HarddiskVolume*\…`), so writable-path and LOLBin rules fire on real Falcon values.
- IOA regex values are normalized to comparable paths, so the process rules
  (EXCL-PROC-001/002) evaluate IOA exclusions instead of silently skipping them.
- EXCL-PATH-001 no longer mis-scores an any-volume prefix as a drive-root critical.
