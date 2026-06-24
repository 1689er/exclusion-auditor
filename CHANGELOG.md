# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://example.com/compare
[0.1.0]: https://example.com/releases/0.1.0
