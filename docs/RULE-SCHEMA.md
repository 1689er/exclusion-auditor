# Risk Rule Schema

Every rule is a YAML document. Rules are grouped into category files under `rules/`,
but each rule is self-contained and could be split into its own file later (Sigma-style)
without changing the engine.

The engine evaluates each rule against every **normalized exclusion** (see
`../README.md` for the normalized model) and emits a finding when the rule's `match`
block evaluates to `true`.

## Rule fields

| Field | Required | Description |
|-------|----------|-------------|
| `id` | yes | Stable identifier, e.g. `EXCL-PATH-002`. Never reused. |
| `name` | yes | Short human title. |
| `severity` | yes | `critical` \| `high` \| `medium` \| `low` \| `info`. |
| `category` | yes | `extension` \| `path` \| `process` \| `scope` \| `hygiene`. |
| `mitre` | no | ATT&CK technique id(s), e.g. `T1562.001`. |
| `applies_to_types` | yes | Which normalized exclusion `type`s this rule considers. Use `["*"]` for all. |
| `description` | yes | What the rule looks for, one or two sentences. |
| `rationale` | yes | *Why* it is risky — the attacker's-eye view. This is the part that earns trust. |
| `match` | yes | Condition tree (see below). |
| `remediation` | yes | Concrete fix the admin should apply. |
| `references` | no | URLs backing the rationale. |
| `enabled` | no | Defaults to `true`. Set `false` to ship a rule disabled. |
| `requires` | no | Engine capability needed: `metadata` (created_at, etc.) or `corpus` (cross-record analysis like duplicates). Rules without this run on a single exclusion in isolation. |

## The `match` condition tree

A `match` is a single condition or a combinator. Combinators nest freely.

Combinators:
- `all_of: [ ... ]` — AND
- `any_of: [ ... ]` — OR
- `not: { ... }` — negation

Leaf conditions (operators the engine implements):

| Operator | Argument | True when... |
|----------|----------|--------------|
| `pattern_kind_in` | list | the exclusion's `pattern_kind` is in the list |
| `extension_in` | list | the value's file extension (lowercased, no dot) is in the list |
| `value_regex` | regex | the regex matches the normalized `value` (case-insensitive) |
| `path_under` | `ref:<datafile>` or list | the value's path resolves under any listed base path (after env-var + `%USERPROFILE%` normalization) |
| `wildcard_at_depth_lte` | integer N | the value contains a `*`/`?` at path segment depth ≤ N (a broad wildcard) |
| `process_name_in` | `ref:<datafile>` or list | the value's process/file name is in the list |
| `overlaps_known_path` | `ref:<datafile>` | the excluded directory contains, or sits above, a listed sensitive binary/location |
| `scope_equals` | string | the exclusion `scope` equals the value (e.g. `global`) |
| `field_empty` | field name | that normalized field is empty/missing (e.g. `comment`) |
| `age_days_gte` | integer | `created_at` is at least N days ago (needs `requires: metadata`) |

### `ref:` data files
A value of `ref:writable-paths` loads the `entries:` list from `data/writable-paths.yml`.
This keeps the volatile lists (writable dirs, interpreters, LOLBins) out of the rules so the
community can grow them with small, reviewable PRs.

## Scoring
- A finding inherits its rule's `severity`.
- A `scope` rule that matches can **escalate** another finding on the same exclusion by one
  level (e.g. a `high` path exclusion applied globally becomes `critical`). The engine applies
  escalation after base scoring; see `rules/scope-and-hygiene.yml`.

## Suppressions
Findings can be silenced via `examples/suppressions.yml`. A suppression matches on
`rule_id` + an exclusion `value` (exact or regex) and requires a `reason`. Suppressed findings
are still reported under a `suppressed` section so they never silently disappear.
