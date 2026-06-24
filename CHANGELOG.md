# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
### Added
- `--check-scopes` — read-only pre-flight that the Falcon API client has the required
  exclusion read scopes, before running a full audit. (#4)
- `--share-out` now auto-verifies the file it writes is safe to share.
- Report now separates **Risk findings** (critical/high/medium) from a compact **Hygiene**
  section so low-severity governance noise no longer buries real findings.
- `--verify-share PATH` — scan a file for likely-sensitive content before sharing
  (encoding-aware, catches UTF-16). (#2, #7)
- `--summary-only` — sanitized output with only the aggregate summary. (#5)
- `--salt-file PATH` — persistent salt for stable value tokens across runs. (#8)
- Confidential-output guards: `.gitignore` patterns for full reports and salt files. (#7)

### Fixed
- IOA exclusions no longer always report `has_comment=true` (comment now maps to the admin
  description only), so the hygiene rule can fire on undocumented IOA exclusions. (#6)

### Added (earlier in cycle)
- **Sanitized/shareable reports** for enterprise use: `--redact` (sanitized stdout) and
  `--share-out PATH` (sanitized JSON file). Strips exclusion values, paths, admin
  identities, comments, host group names, and tenant IDs; replaces each value with a
  per-run hashed token so correlation survives but values can't be recovered.
- `docs/ENTERPRISE.md` documenting security posture and safe-sharing workflow.
- Community feedback path: GitHub Discussions enabled, `docs/SHARING.md` safe-sharing
  guide, and issue templates updated to request sanitized (`--share-out`) reports only.
- `project.urls` metadata (homepage, repository, issues, changelog).
- Default reports now labelled CONFIDENTIAL to prevent accidental sharing.

### Security
- Pinned GitHub Actions to commit SHAs (supply-chain hardening).
- Added a CodeQL static-analysis workflow.

## [0.1.0] - 2026-06-24
### Added
- Vendor-agnostic risk engine for EDR/NGAV exclusions with a YAML rule library
  (extension, path, process, scope, and hygiene rules), data-driven `ref:` lists
  (writable paths, interpreters, LOLBins), scope-based escalation, and suppressions.
- **CrowdStrike Falcon adapter** (read-only): ML, IOA, and Sensor Visibility
  exclusions via FalconPy, with pagination and host-group name resolution.
- **Import adapter**: audit exclusions exported to JSON or CSV (any vendor, no creds).
- CLI with `table` / `json` / `markdown` output and a `--ci` gate.
- Documentation: rule schema, configuration, and adapter guides.
- Test suite covering engine behavior and CrowdStrike normalization (no creds needed).
