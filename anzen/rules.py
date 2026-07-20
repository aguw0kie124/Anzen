# Copyright 2026 Siddharth
# SPDX-License-Identifier: Apache-2.0

"""Rule loading, matching, and session scanning.

Rules are YAML documents validated against the `Rule` schema — `explanation`
and `remediation` are required, so every finding carries its own fix guidance.
"""

from __future__ import annotations

import json
import re
from importlib import resources
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, Field, field_validator

from .store import Action, ActionType, Finding, Store

EXCERPT_CONTEXT = 60


class RuleMatch(BaseModel):
    field: Literal["input", "output", "name", "raw"] = "raw"
    any_regex: list[str] = Field(min_length=1)
    ignore_case: bool = False

    @field_validator("any_regex")
    @classmethod
    def _compilable(cls, patterns: list[str]) -> list[str]:
        for pattern in patterns:
            re.compile(pattern)
        return patterns


class Rule(BaseModel):
    id: str
    title: str
    severity: Literal["critical", "high", "medium", "low", "info"]
    owasp_llm: str = ""
    applies_to: list[ActionType] | None = None  # None = all action types
    match: RuleMatch
    explanation: str = Field(min_length=10)
    remediation: str = Field(min_length=10)

    def compiled(self) -> list[re.Pattern[str]]:
        flags = re.IGNORECASE if self.match.ignore_case else 0
        return [re.compile(p, flags) for p in self.match.any_regex]


def load_rules(extra_dir: str | Path | None = None) -> list[Rule]:
    """Load the built-in rule pack plus any `*.yaml` files in extra_dir."""
    documents: list[tuple[str, str]] = []
    builtin = resources.files("anzen").joinpath("rules_builtin.yaml")
    documents.append(("builtin", builtin.read_text()))
    if extra_dir:
        for path in sorted(Path(extra_dir).glob("*.yaml")):
            documents.append((str(path), path.read_text()))

    rules: list[Rule] = []
    seen_ids: set[str] = set()
    for origin, text in documents:
        entries = yaml.safe_load(text) or []
        if not isinstance(entries, list):
            raise ValueError(f"{origin}: rule file must be a YAML list of rules")
        for entry in entries:
            rule = Rule.model_validate(entry)
            if rule.id in seen_ids:
                raise ValueError(f"{origin}: duplicate rule id {rule.id}")
            seen_ids.add(rule.id)
            rules.append(rule)
    return rules


def _field_text(action: Action, field: str) -> str:
    if field == "input":
        return action.input
    if field == "output":
        return action.output
    if field == "name":
        return action.name
    # raw: everything we have about the action
    return "\n".join(
        [action.name, action.input, action.output,
         json.dumps(action.raw_attributes, default=str)]
    )


def _excerpt(text: str, match: re.Match[str]) -> str:
    start = max(0, match.start() - EXCERPT_CONTEXT)
    end = min(len(text), match.end() + EXCERPT_CONTEXT)
    prefix = "…" if start > 0 else ""
    suffix = "…" if end < len(text) else ""
    return prefix + text[start:end].replace("\n", " ") + suffix


def match_action(action: Action, rules: list[Rule]) -> list[Finding]:
    """Run every rule against one action (at most one finding per rule)."""
    findings: list[Finding] = []
    for rule in rules:
        if rule.applies_to is not None and action.action_type not in rule.applies_to:
            continue
        text = _field_text(action, rule.match.field)
        if not text:
            continue
        for pattern in rule.compiled():
            match = pattern.search(text)
            if match:
                findings.append(
                    Finding(
                        session_id=action.session_id,
                        action_id=action.id,
                        rule_id=rule.id,
                        severity=rule.severity,
                        owasp_llm=rule.owasp_llm,
                        title=rule.title,
                        explanation=rule.explanation,
                        remediation=rule.remediation,
                        matched_excerpt=_excerpt(text, match),
                    )
                )
                break  # one finding per (rule, action)
    return findings


def scan_actions(actions: list[Action], rules: list[Rule]) -> list[Finding]:
    return [finding for action in actions for finding in match_action(action, rules)]


def scan_session(store: Store, session_id: str, rules: list[Rule]) -> list[Finding]:
    """Run deterministic rules over a session and persist the findings (idempotent)."""
    actions = store.get_actions(session_id)
    findings = scan_actions(actions, rules)
    store.replace_findings(session_id, "rule", findings)
    return findings
