---
name: False positive
about: A rule flagged a legitimate, well-scoped exclusion
title: "[FP] <rule id> fires on <short description>"
labels: false-positive
---

**Rule that fired**
e.g. `EXCL-PATH-002`

**Exclusion shape (sanitize real values!)**
```
type:         ml | ioa | sensor_visibility | path | extension | process
value:        <sanitized>
pattern_kind: path | wildcard | extension | process | hash
scope:        global | host_group:<name>
```

**Why this exclusion is legitimate**
What makes it safe / well-scoped?

**Suggested fix**
Tighten the rule? Add to a data list? Suppression guidance?

**Environment**
- adapter: import | crowdstrike
- version / commit:
