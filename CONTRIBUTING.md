# Contributing

Thanks for helping make EDR/NGAV exclusions safer. This project lives or dies by
its **risk-rule library**, and that's exactly where contributions matter most.

## Ground rule: read-only, always
Adapters may only *read* exclusions — never create, modify, or delete them. Any PR
that adds a write/mutation call to a vendor API will be declined. This is a trust
prerequisite for ops teams.

## Dev setup
```bash
python -m pip install -e ".[dev]"   # editable install + pytest
pytest -q                            # run the suite
exclusion-auditor --config examples/demo.yaml   # try the demo
```
Requires Python 3.9+.

## The most valuable contribution: risk rules
New rules (and data-list entries) are the highest-impact thing you can add.

1. Read [docs/RULE-SCHEMA.md](docs/RULE-SCHEMA.md) for the rule format and the
   available match operators.
2. Add your rule to the appropriate file in [`rules/`](rules/) (or a new file).
   Every rule **must** include:
   - a clear `rationale` (the attacker's-eye view — *why* it's risky),
   - a concrete `remediation`,
   - `references` backing the claim, and
   - a `mitre` mapping where applicable (usually `T1562.001`).
3. If your rule relies on a volatile list (writable paths, interpreters, LOLBins),
   add entries to the relevant file in [`data/`](data/) rather than hard-coding.
4. Add or update a fixture in [`examples/sample-exclusions.json`](examples/sample-exclusions.json)
   and an assertion in [`tests/test_engine.py`](tests/test_engine.py) so the rule's
   behavior is locked in.

### Quality bar (the whole point is signal-to-noise)
A rule that fires on legitimate, well-scoped exclusions is worse than no rule. Before
submitting, confirm your rule does **not** flag the "good" demo exclusion (`demo-005`),
and prefer precise matches over broad ones.

## Reporting a false positive
False positives are first-class bugs here. Open an issue with the **shape** of the
exclusion that was wrongly flagged (sanitize real values) and which rule fired. Use
the *False positive* issue template.

**Only ever share sanitized data** — attach a report produced with `--share-out`, never
the default/full report. See [docs/SHARING.md](docs/SHARING.md) for the safe-sharing guide
(and use **Discussions** for aggregate sanitized reports / tuning).

## Adding an adapter
See the "Writing a new adapter" section in [docs/ADAPTERS.md](docs/ADAPTERS.md). Keep
normalization in pure functions so it unit-tests without credentials, and register
the adapter in `exclusion_auditor/adapters/__init__.py`.

## Pull request checklist
- [ ] `pytest -q` passes
- [ ] New rules have rationale + remediation + references (+ mitre where relevant)
- [ ] No write/mutation calls to any vendor API
- [ ] Does not flag the known-good demo exclusion
- [ ] Docs updated if behavior or config changed

## Commit style
Short imperative subject lines (e.g. `add rule for excluded LNK files`). Group related
changes; keep unrelated changes in separate PRs.
