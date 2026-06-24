# Sharing results safely

The rules in this project improve fastest when they're calibrated against real-world
exclusion data. You can help — **but only ever share sanitized output.**

## The golden rule
> Only share reports produced with **`--share-out`** or **`--redact`**.
> **Never** share the default report — it is CONFIDENTIAL and contains real exclusion
> values, paths, admin identities, comments, host group names, and your tenant ID.

A sanitized report contains only: rule IDs, severities, types, pattern kinds, scope class
(`global`/`scoped`), and a per-run hashed token per value. No values, paths, identities,
group names, or tenant IDs. See [ENTERPRISE.md](ENTERPRISE.md) for exactly what is removed.

## Generate a sanitized report
```bash
exclusion-auditor --config config.yaml --share-out audit.sanitized.json
# or share even less — just the aggregate summary:
exclusion-auditor --config config.yaml --summary-only --format json > summary.json
```

## Verify before you share
Run the built-in scanner on any file before sending it — it flags paths, identities,
emails, GUIDs/CIDs, etc., and is encoding-aware (catches UTF-16 reports from PowerShell):
```bash
exclusion-auditor --verify-share audit.sanitized.json
# -> "SAFE: no obvious sensitive content found"   (exit 0)
#    "UNSAFE: ... do NOT share"                    (exit 1)
```
`SAFE` is a heuristic, not a guarantee — still confirm the file came from `--share-out`/`--redact`.

## Where to share
| You want to... | Use | Link |
|---|---|---|
| Report a noisy rule / false positive | **Issue** (False positive template) | repo → Issues → New issue |
| Propose a new rule | **Issue** (Propose a rule template) | repo → Issues → New issue |
| Share an aggregate sanitized report for tuning | **Discussion** | repo → Discussions |

Both Issues and Discussions accept file attachments — drag in `audit.sanitized.json`.

## Before you share (enterprise checklist)
- [ ] The file was produced with `--share-out` / `--redact` (not the default report).
- [ ] You eyeballed it: only tokens and counts, no real paths/names.
- [ ] Your organization permits sharing **aggregate, sanitized** findings externally.
- [ ] You won't paste literal exclusion values, hostnames, or usernames in the prose either —
      describe the *shape* instead (e.g. "scoped path exclusion under a vendor dir").
- [ ] Transferring the file off a corporate machine complies with your data-handling/DLP policy.

When in doubt, share less: even the **summary block** alone (counts by rule and severity)
is enough for us to spot which rules are too noisy or too quiet.
