"""The audit engine: evaluate rules against exclusions, then apply corpus-level
analysis, scope escalation, and suppressions."""

from __future__ import annotations

from typing import List

from . import matchers
from .datarefs import DataResolver
from .models import Finding, NormalizedExclusion, bump_severity, severity_rank
from .paths import normalize_segments, path_is_under
from .rules import Rule
from .suppressions import Suppression

# Categories that scope-escalation should raise. Hygiene/scope findings are
# governance noise and are deliberately left un-escalated.
ESCALATABLE_CATEGORIES = {"extension", "path", "process"}


class Engine:
    def __init__(self, rules: List[Rule], data: DataResolver,
                 suppressions: List[Suppression] | None = None):
        self.rules = rules
        self.data = data
        self.suppressions = suppressions or []

    def run(self, exclusions: List[NormalizedExclusion]) -> List[Finding]:
        findings: List[Finding] = []
        for excl in exclusions:
            findings.extend(self._evaluate_one(excl))
        findings.extend(self._corpus_findings(exclusions))
        self._apply_escalation(findings, exclusions)
        self._apply_suppressions(findings)
        return findings

    # --- per-exclusion rules ---------------------------------------------
    def _evaluate_one(self, excl: NormalizedExclusion) -> List[Finding]:
        out = []
        for rule in self.rules:
            if not rule.enabled or not rule.applies_to(excl.type):
                continue
            if rule.requires == "corpus":
                continue  # handled in _corpus_findings
            if rule.requires == "metadata" and not excl.created_at:
                continue
            if matchers.evaluate(rule.match, excl, self.data):
                out.append(self._finding(rule, excl))
        return out

    def _finding(self, rule: Rule, excl: NormalizedExclusion) -> Finding:
        return Finding(
            rule_id=rule.id,
            rule_name=rule.name,
            severity=rule.severity,
            base_severity=rule.severity,
            category=rule.category,
            exclusion=excl,
            remediation=rule.remediation,
            mitre=rule.mitre,
            references=list(rule.references),
        )

    # --- corpus-level rules (duplicate / overlap) ------------------------
    def _corpus_findings(self, exclusions: List[NormalizedExclusion]) -> List[Finding]:
        corpus_rules = [r for r in self.rules if r.enabled and r.requires == "corpus"]
        if not corpus_rules:
            return []
        out = []
        for rule in corpus_rules:
            for excl in exclusions:
                if not rule.applies_to(excl.type):
                    continue
                covering = self._covered_by(excl, exclusions)
                if covering is not None:
                    f = self._finding(rule, excl)
                    f.remediation = (
                        f"Covered by broader exclusion '{covering.value}' "
                        f"({covering.id}). " + rule.remediation
                    )
                    out.append(f)
        return out

    @staticmethod
    def _covered_by(excl, exclusions):
        """Find a *distinct, broader, non-near-root* exclusion that already
        covers `excl`. Near-root coverers are skipped so a catastrophic C:\\*
        doesn't flag everything else as merely 'redundant'."""
        for other in exclusions:
            if other.id == excl.id or other.value == excl.value:
                continue
            other_segs = normalize_segments(other.value)
            while other_segs and other_segs[-1] in ("*", "?"):
                other_segs.pop()
            if len(other_segs) < 2:           # near-root / single segment: skip
                continue
            if path_is_under(excl.value, other.value):
                return other
        return None

    # --- scope escalation -------------------------------------------------
    def _apply_escalation(self, findings, exclusions):
        # Which exclusion ids triggered an escalating (scope) rule?
        escalating_ids = {
            f.exclusion.id for f in findings
            if self._rule_escalates(f.rule_id)
        }
        for f in findings:
            if (f.exclusion.id in escalating_ids
                    and f.category in ESCALATABLE_CATEGORIES):
                raised = bump_severity(f.severity, 1)
                if raised != f.severity:
                    f.severity = raised
                    f.escalated = True
                    f.escalation_note = "raised one level: applied at global scope"

    def _rule_escalates(self, rule_id: str) -> bool:
        for r in self.rules:
            if r.id == rule_id:
                return r.escalates
        return False

    # --- suppressions -----------------------------------------------------
    def _apply_suppressions(self, findings):
        for f in findings:
            for s in self.suppressions:
                if s.matches(f.rule_id, f.exclusion.value):
                    f.suppressed = True
                    f.suppression_reason = s.reason
                    break


def sort_findings(findings: List[Finding]) -> List[Finding]:
    """Highest severity first, then by exclusion id for stable output."""
    return sorted(
        findings,
        key=lambda f: (-severity_rank(f.severity), f.exclusion.id, f.rule_id),
    )
