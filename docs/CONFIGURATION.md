# Configuration

The tool is driven by a single YAML config passed with `--config`. Copy one of
the examples ([`examples/demo.yaml`](../examples/demo.yaml),
[`examples/crowdstrike.yaml`](../examples/crowdstrike.yaml)) to `config.yaml`
(git-ignored) and edit. Relative paths resolve against your current working
directory, so run from the project root.

Everything environment-specific lives here — you configure the tool to your
environment without editing any code.

## Keys

| Key | Default | Description |
|-----|---------|-------------|
| `adapter` | `import` | Which source to pull from: `import` or `crowdstrike`. See [ADAPTERS.md](ADAPTERS.md). |
| `<adapter>` | — | A block named after the adapter holding its options (e.g. `import:` or `crowdstrike:`). |
| `rules.paths` | `[rules]` | Files/dirs of rule YAML. Listed in order; **later definitions override earlier ones by `id`**, so your custom dir can shadow a bundled rule. |
| `data_dir` | `data` | Directory holding the `ref:` data lists (`writable-paths.yml`, `interpreters.yml`, `lolbins.yml`). |
| `data_overrides` | `{}` | Map a `ref:` name to a replacement file, e.g. `writable-paths: ./my-paths.yml`. |
| `suppressions` | — | Path to a suppressions file. See below. |
| `output.format` | `table` | `table` \| `json` \| `markdown`. |
| `output.min_severity` | `info` | Hide active findings below this. Suppressed findings are always shown. |
| `ci.fail_on` | `critical` | With `--ci`, exit non-zero when any active finding is at/above this severity. |

## CLI overrides
`--format`, `--min-severity`, and `--ci` override the config at runtime. `--config`
is required.

## Tuning to your environment (the important part)
Three layers let you adapt without forking:

1. **Custom rules** — add a directory to `rules.paths`. Reuse a bundled rule's
   `id` to override it, or use a new `id` to add one. Format: [RULE-SCHEMA.md](RULE-SCHEMA.md).
2. **Extend data lists** — point `data_overrides` at your own
   `writable-paths.yml` / `interpreters.yml` / `lolbins.yml` to add your vendor
   paths, approved interpreters, etc.
3. **Suppressions** — silence reviewed-and-accepted findings.

## Suppressions
Each entry needs a `reason`; suppressed findings are still reported (under a
`suppressed` section) so they never silently vanish.

```yaml
suppressions:
  - rule_id: EXCL-PATH-002
    value: 'C:\Users\*\AppData\Local\Temp'   # exact match
    reason: Accepted for vendor agent; compensated by app-control. Owner j.admin.
    expires: 2026-09-01                       # optional; after this the finding re-appears
  - rule_id: EXCL-HYG-001
    value_regex: '^C:\\Program Files\\LOBApp\\.*'   # or a regex match
    reason: Owner/ticket tracked in CMDB.
```

A suppression matches when `rule_id` matches **and** (`value` exact OR
`value_regex` matches the exclusion's value). Omit both to suppress a rule
entirely. Expired suppressions are ignored. See
[`examples/suppressions.yml`](../examples/suppressions.yml).
