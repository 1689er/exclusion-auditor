# Adapters

An adapter pulls exclusions from a source and normalizes them. Every adapter is
**read-only** — it may only read exclusions, never create/modify/delete them.

Select an adapter with the top-level `adapter:` key in your config; its options
go in a block named after it.

---

## `import` — files (vendor-agnostic, no credentials)

Audit exclusions you've already exported to JSON or CSV. Works for any vendor and
needs no API access — ideal for a first run, air-gapped review, or non-Falcon shops.

```yaml
adapter: import
import:
  path: ./my-exclusions.json     # .json or .csv
```

**JSON**: a list of objects (or `{"exclusions": [...]}`). **CSV**: a header row with
the same field names. Fields map to the normalized model:

| Field | Required | Notes |
|-------|----------|-------|
| `id` | yes | any unique identifier |
| `type` | yes | `ml` \| `ioa` \| `sensor_visibility` \| `path` \| `extension` \| `process` |
| `value` | yes | the excluded path / extension / process |
| `pattern_kind` | no | `path` \| `wildcard` \| `extension` \| `process` \| `hash` (defaults to `path`) |
| `scope` | no | `global` or `host_group:<name>` (defaults to `global`) |
| `created_by`, `created_at`, `comment` | no | drive the hygiene rules; `created_at` is ISO-8601 |

See [`examples/sample-exclusions.json`](../examples/sample-exclusions.json).

---

## `crowdstrike` — Falcon API (read-only)

Pulls the three exclusion collections (ML, IOA, Sensor Visibility) directly from
your tenant via [FalconPy](https://www.falconpy.io/).

### 1. Install the optional dependency
```bash
pip install crowdstrike-falconpy        # or: pip install '.[crowdstrike]'
```

### 2. Create an API client (read-only)
Falcon console → **Support and resources → API clients & keys → Create API client**.
Grant **Read** only on:

| Scope | Why |
|-------|-----|
| **ML Exclusions: Read** | pull ML exclusions |
| **IOA Exclusions: Read** | pull IOA exclusions |
| **Sensor Visibility Exclusions: Read** | pull sensor visibility exclusions |
| Host Groups: Read *(optional)* | resolve host-group names for scoped exclusions |

Do **not** grant any Write scope. This tool never needs it.

### 3. Provide credentials via environment variables
Secrets are read from the environment, never from the config file.
```powershell
$env:FALCON_CLIENT_ID     = "<client id>"
$env:FALCON_CLIENT_SECRET = "<client secret>"
```

### 4. Configure and run
```yaml
adapter: crowdstrike
crowdstrike:
  cloud: us-1                 # us-1 | us-2 | eu-1 | us-gov-1 | us-gov-2
  client_id_env: FALCON_CLIENT_ID
  client_secret_env: FALCON_CLIENT_SECRET
  exclusion_types: [ml, ioa, sensor_visibility]
  member_cids: []            # optional child CIDs (Flight Control / MSSP)
  resolve_group_names: true  # host group IDs -> names (needs Host Groups: Read)
```
```bash
exclusion-auditor --config config.yaml
```

### Notes & current limitations
- **IOA values are regexes.** IOA exclusions are behavioral; the adapter maps
  `ifn_regex` (image-file-name regex) to `value` and `pattern_kind: process`, and
  keeps `name`/`pattern_name`/`cl_regex` in the comment. Path-style matchers are
  approximate on regex values — tighten the process rules for your environment if
  needed.
- **Host group names.** Scoped exclusions show host group *names* when
  `resolve_group_names: true` (the default) and the client has **Host Groups: Read**.
  Without that scope the tool prints a warning and falls back to group IDs — set
  `resolve_group_names: false` to skip the lookup entirely.
- **`cloud` vs `base_url`.** Set `base_url` to override the region mapping.
- **Pagination** is handled automatically; only `query_exclusions` and
  `get_exclusions` are ever called.

---

## Writing a new adapter
1. Subclass `Adapter` (`exclusion_auditor/adapters/base.py`) and implement
   `fetch() -> list[NormalizedExclusion]`. Keep it read-only.
2. Put pure normalization in standalone functions so they unit-test without
   network/credentials (see `crowdstrike.py` + `tests/test_crowdstrike.py`).
3. Register it in `exclusion_auditor/adapters/__init__.py`.
