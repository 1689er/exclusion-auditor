---
name: False positive
about: A rule flagged a legitimate, well-scoped exclusion
title: "[FP] <rule id> fires on <short description>"
labels: false-positive
---

> ⚠️ **Share only sanitized data.** Do not paste real exclusion values, paths, hostnames,
> usernames, or your tenant ID. Attach a report produced with `--share-out` (sanitized),
> never the default/full report. See [docs/SHARING.md](../../blob/main/docs/SHARING.md).

**Rule that fired**
e.g. `EXCL-PATH-002`

**Sanitized details**
Attach your `audit.sanitized.json` (drag-drop), or paste the relevant rows. You may also
describe the exclusion's *shape* in words — e.g. "a scoped path exclusion under a vendor
directory in ProgramData" — but never the literal value.

```
type:         ml | ioa | sensor_visibility | path | extension | process
pattern_kind: path | wildcard | extension | process | hash
scope_class:  global | scoped
```

**Why this exclusion is legitimate**
What makes it safe / well-scoped? (No real paths — describe the shape.)

**Suggested fix**
Tighten the rule? Add to a data list? Suppression guidance?

**Environment**
- adapter: import | crowdstrike
- version / commit:
