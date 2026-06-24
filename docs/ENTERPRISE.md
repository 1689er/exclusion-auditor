# Enterprise use & data handling

This tool is built to run inside enterprises against production EDR/NGAV tenants.
This page covers its security posture and how to share findings without leaking
company data.

## Security posture
- **Read-only.** Adapters only ever *read* exclusions (CrowdStrike: `query_exclusions`,
  `get_exclusions`, `get_host_groups`). No create/update/delete calls exist in the code.
- **No telemetry, no third-party egress.** The tool makes network calls *only* to the
  vendor API you configure (e.g. your Falcon cloud). It phones nothing home. Redaction
  and reporting happen entirely locally.
- **Credentials from the environment only.** API secrets are read from environment
  variables you name in config; they are never read from the config file, never written
  to disk, and never printed.
- **Minimal scope.** Grant the API client read-only access to just the exclusion
  collections (+ Host Groups: Read for name resolution). See [ADAPTERS.md](ADAPTERS.md).

## Data classification of the output
| Output | Sensitivity | Contains |
|--------|-------------|----------|
| Default report (table/JSON/markdown) | **CONFIDENTIAL** | real exclusion values/paths, `created_by` (admin identities), comments, host group names, tenant CID |
| Sanitized report (`--redact` / `--share-out`) | **Shareable** | rule ids, severities, types, pattern kinds, scope class (global/scoped), and a per-run hashed value token — nothing else |

Treat the default report as confidential company data: store it where corporate data
belongs, don't commit it, don't paste it externally.

## Sharing safely (built in)
To report a false positive upstream, or to hand findings to another team, produce a
sanitized report — it is safe by construction:

```bash
# write a sanitized JSON file (safe to share externally)
exclusion-auditor --config config.yaml --share-out exclusion-audit.sanitized.json

# or print sanitized output in any format
exclusion-auditor --config config.yaml --redact --format markdown
```

What sanitization removes/transforms:
- exclusion **values/paths** → replaced by a hashed `value_token`
- **host group names** → reduced to `scope_class: global | scoped`
- `created_by`, `created_at`, **comments**, **tenant CID**, exclusion ids → dropped

The token is computed with a random per-run salt that is never stored, so:
- *within* one report you can still see that several findings are the same exclusion
  (same token), which helps triage;
- the value cannot be reversed, and tokens cannot be correlated across separate reports.

## Recommended enterprise workflow
1. Run with the full (confidential) report and keep it in approved storage for your own
   triage of specific findings.
2. Generate a sanitized report (`--share-out`) for anything that leaves your control —
   upstream bug reports, cross-team sharing, tickets.
3. In CI/CD, gate with `--ci` (non-zero exit at/above `ci.fail_on`); the pipeline only
   needs the pass/fail, not the values.
4. If you created an API client just for an assessment, disable or delete it afterward.

## CI/CD
The included GitHub Actions are least-privilege (`contents: read`) and pinned to commit
SHAs. For your own pipelines, pass credentials via your secret store as environment
variables and run `exclusion-auditor --config config.yaml --ci`.
