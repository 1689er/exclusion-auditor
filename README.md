# Exclusion Auditor

Audit your NGAV/EDR **exclusions** for security risk and hygiene before an attacker does.

Exclusions are the least-governed, highest-risk configuration in any endpoint security
deployment. Adding or abusing one is a named MITRE ATT&CK technique
([T1562.001 — Impair Defenses](https://attack.mitre.org/techniques/T1562/001/)), yet most
teams accumulate hundreds of exclusions over years with no record of why they exist or how
dangerous they are. Commercial tools flag "risky exclusions" for one vendor inside a closed
portal ([Huntress, for managed Defender](https://support.huntress.io/hc/en-us/articles/4404005108371-Exclusions-for-Managed-Microsoft-Defender-Antivirus)).
There is no open, vendor-agnostic equivalent — and nothing for CrowdStrike Falcon.

This project is that tool: a **read-only** auditor with a vendor-agnostic risk engine and
pluggable adapters, CrowdStrike Falcon first.

> **Read-only by design.** The tool never modifies exclusions. Adapters request the
> minimum read scope only. This is a hard rule, not a default — an ops team must be able to
> trust it in production.

## Quickstart (zero credentials)

Requires Python 3.9+.

```bash
pip install -e .                                    # or: pip install pyyaml
exclusion-auditor --config examples/demo.yaml       # audits the bundled demo set
# without installing:
python -m exclusion_auditor.cli --config examples/demo.yaml
```

The demo runs the import adapter against `examples/sample-exclusions.json`, so it works with
no API access. To audit your own environment, point the config at your exported exclusions
(import adapter) or, soon, at the CrowdStrike adapter. Other flags: `--format json|markdown`,
`--min-severity high`, and `--ci` (exit non-zero at/above `ci.fail_on`).

## How it works

```
adapters (per vendor)            core (vendor-agnostic)
  crowdstrike  ─┐                 ┌─ risk rule engine
  defender     ─┼─► normalized ──►│   + rule library (rules/*.yml)
  import (CSV/  │    exclusion    │   + data refs   (data/*.yml)
  JSON)        ─┘     model       │   + suppressions
                                  └─► reports: console / JSON / Markdown / CI exit code
```

Adapters available today: **`crowdstrike`** (Falcon ML/IOA/Sensor Visibility, read-only via
FalconPy) and **`import`** (JSON/CSV, any vendor, no credentials). The import adapter means
anyone — any vendor, or with no API access at all — can export exclusions and still get a full
risk report; it's also how you demo and test without credentials. Setup details:
[docs/ADAPTERS.md](docs/ADAPTERS.md) · all config keys: [docs/CONFIGURATION.md](docs/CONFIGURATION.md).

### Normalized exclusion model
Every adapter maps its vendor's exclusions into this shape:

| Field | Notes |
|-------|-------|
| `id` | vendor's exclusion id |
| `platform` | `crowdstrike` \| `defender` \| `import` \| ... |
| `tenant_cid` | tenant / CID |
| `type` | `ml` \| `ioa` \| `sensor_visibility` \| `path` \| `extension` \| `process` |
| `value` | the excluded path / extension / process |
| `pattern_kind` | `path` \| `wildcard` \| `extension` \| `process` \| `hash` |
| `scope` | `global` or `host_group:<name>` |
| `created_by`, `created_at`, `comment` | governance metadata (drives hygiene rules) |

CrowdStrike maps cleanly: the three FalconPy service collections
([ML](https://www.falconpy.io/Service-Collections/Ml-Exclusions.html),
[IOA](https://www.falconpy.io/Service-Collections/IOA-Exclusions.html),
[Sensor Visibility](https://www.falconpy.io/Service-Collections/Sensor-Visibility-Exclusions.html))
become the `ml` / `ioa` / `sensor_visibility` types.

### Rules
Risk rules live in [`rules/`](rules/) as YAML and reference shared data lists in
[`data/`](data/) (writable paths, interpreters, LOLBins) so the volatile knowledge grows via
small PRs — Sigma-style, but for exclusions. The rule format is documented in
[`docs/RULE-SCHEMA.md`](docs/RULE-SCHEMA.md).

Starter rules shipped:

| ID | Severity | Catches |
|----|----------|---------|
| EXCL-EXT-001 | critical | executable/script extension excluded (`*.exe`, `*.ps1`, ...) |
| EXCL-EXT-002 | high | macro-doc / archive extension excluded |
| EXCL-PATH-001 | critical | root / near-root path excluded (`C:\`, `C:\Users`) |
| EXCL-PATH-002 | high | user-writable directory excluded (Temp, AppData, ...) |
| EXCL-PATH-003 | medium | wildcard inside a path |
| EXCL-PATH-004 | high | exclusion overlaps a system/LOLBin location |
| EXCL-PROC-001 | high | interpreter/LOLBin excluded from behavioral inspection |
| EXCL-PROC-002 | high | process exclusion via wildcard/writable path |
| EXCL-SCOPE-001 | medium* | risky exclusion applied globally (*escalates other findings) |
| EXCL-HYG-001 | low | no description/owner |
| EXCL-HYG-002 | low | stale (>1y, unmodified) |
| EXCL-HYG-003 | info | duplicate/overlapping |

### Suppressions
Reviewed-and-accepted findings are silenced via
[`examples/suppressions.yml`](examples/suppressions.yml) — every suppression needs a reason,
and suppressed findings are still reported (never silently dropped). This keeps the tool
quiet enough to live with, which is what kills noisy scanners.

## What the demo produces
[`examples/sample-exclusions.json`](examples/sample-exclusions.json) is a normalized demo set.
Running it yields **12 findings across 3 exclusions** (the other 2 are suppressed / clean):

| Exclusion | Findings |
|-----------|----------|
| `demo-001` `*.ps1`, global, no comment, legacy | **EXCL-EXT-001 (critical)**, EXCL-SCOPE-001 (med), EXCL-HYG-001 (low), EXCL-HYG-002 (low) |
| `demo-002` AppData\Temp, scoped, documented, recent | EXCL-PATH-002 (high) — **suppressed** via suppressions.yml |
| `demo-003` `C:\*`, global, no comment, ancient | **EXCL-PATH-001 (critical)**, **EXCL-PATH-004 (critical, escalated)**, EXCL-SCOPE-001 (med), EXCL-HYG-001, EXCL-HYG-002 |
| `demo-004` `powershell.exe` IOA, global, documented | **EXCL-PROC-001 (high→critical, escalated by global scope)**, EXCL-SCOPE-001 (med), EXCL-HYG-002 |
| `demo-005` signed LOB exe, scoped, documented, recent | none — this is what a *good* exclusion looks like |

`demo-005` producing **zero** findings is the point: a specific, signed, scoped, documented
exclusion is exactly what the tool should *not* flag. That's the signal-to-noise bar.

## Roadmap
- **v0.1 — done.** Rule engine, import + CrowdStrike (read-only) adapters, table/JSON/Markdown
  reports, `--ci` gate, suppressions, and a pytest suite (`pytest -q`).
- **v0.2** — more rules, group-name resolution for scoped Falcon exclusions, Defender adapter,
  HTML report.
- **Phase 2 (hygiene → detection)** — watch Falcon's exclusion **audit log** for newly added
  suspicious exclusions and alert. That turns this from a point-in-time audit into live
  T1562.001 detection.

## Tests
```bash
pip install '.[dev]'   # pytest
pytest -q              # 18 tests: engine behavior + CrowdStrike normalization (no creds needed)
```

## Design rules (don't compromise these)
1. **Read-only.** Minimum scope. Never writes.
2. **Tunable from day one.** Suppressions exist in v0.1, or real findings drown in legitimate exclusions.
3. **Calibrate against a real tenant** before publishing severities.
4. **Never store credentials.** OAuth2 client creds from env/secret store, nothing on disk.

## Contributing & contact
Contributions — especially new risk rules — are welcome; see
[CONTRIBUTING.md](CONTRIBUTING.md). Report security issues privately per
[SECURITY.md](SECURITY.md). Maintainer: Justin Hickman (jch1689@mail.com).
