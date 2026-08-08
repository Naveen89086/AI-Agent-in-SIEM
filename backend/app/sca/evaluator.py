"""Deterministic check evaluation for SCA.

Applies a ``CheckRule`` operator to an actual value read from an endpoint and
the rule's expected value. This module never decides what to read - collectors
produce the evidence - and it never fabricates a result: ``apply_operator``
only compares evidence.
"""

import re
from typing import Any

OPERATORS = (
    "eq",
    "neq",
    "gt",
    "gte",
    "lt",
    "lte",
    "contains",
    "not_contains",
    "startswith",
    "endswith",
    "regex",
    "exists",
    "not_exists",
    "in",
    "not_in",
)

_OPERATOR_ALIASES = {
    "equal": "eq",
    "not_equal": "neq",
    "not_contains": "not_contains",
    "=": "eq",
    "==": "eq",
    "!=": "neq",
    ">": "gt",
    ">=": "gte",
    "<": "lt",
    "<=": "lte",
    "contain": "contains",
    "regex_match": "regex",
    "in_list": "in",
}

_TRUTHY = {"yes", "true", "enabled", "1", "present", "present"}
_FALSY = {"no", "false", "disabled", "0", "none", "absent", "na", "n/a"}


def normalize(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def extract_value(pattern: str, actual: Any) -> str | None:
    """Extract a comparable value from collected evidence.

    Returns the first capture group (or the whole match when the pattern has no
    groups) trimmed, or ``None`` when the pattern does not match. Multi-line
    patterns are enabled so line-anchored extraction from command output works.
    """
    try:
        match = re.search(pattern, str(actual or ""), re.MULTILINE)
    except re.error:
        return None
    if match is None:
        return None
    groups = match.groups()
    value = match.group(1) if groups else match.group(0)
    return value.strip() if value is not None else None


def evaluate_rule(rule, actual: Any) -> bool:
    """Evaluate a rule against collected evidence.

    When the rule carries an extraction ``pattern``, the value is first
    extracted from the evidence and then compared against the rule's
    ``expected_value`` with its ``operator`` (numeric operators are
    numeric-aware). A rule that cannot be extracted is a genuine failure
    (the requested value is not present in the evidence).
    """
    pattern = getattr(rule, "pattern", None)
    if pattern:
        extracted = extract_value(pattern, actual)
        if extracted is None:
            return False
        return apply_operator(rule.operator, extracted, rule.expected_value)
    return apply_operator(rule.operator, actual, rule.expected_value)


def apply_operator(operator: str, actual: Any, expected: Any) -> bool:
    """Return True when the actual value satisfies the rule.

    ``operator`` supports the names in ``OPERATORS`` plus a few aliases. An
    unknown operator is treated as an equality comparison (never raises).
    """
    op = _OPERATOR_ALIASES.get(operator, operator)
    actual_s = normalize(actual)
    expected_s = normalize(expected)

    if op in ("eq", "exists"):
        if expected_s.lower() in _TRUTHY:
            return bool(actual_s) and actual_s.lower() not in _FALSY
        if expected_s.lower() in _FALSY:
            return actual_s.lower() in _FALSY or not actual_s
        return actual_s == expected_s
    if op == "neq":
        return actual_s != expected_s
    if op == "not_exists":
        return not bool(actual_s)
    if op == "contains":
        return bool(actual_s) and expected_s.lower() in actual_s.lower()
    if op == "not_contains":
        return bool(actual_s) and expected_s.lower() not in actual_s.lower()
    if op == "startswith":
        return actual_s.lower().startswith(expected_s.lower())
    if op == "endswith":
        return actual_s.lower().endswith(expected_s.lower())
    if op == "regex":
        try:
            return re.search(expected_s, actual_s) is not None
        except re.error:
            return False
    if op == "in":
        tokens = {t.strip().lower() for t in expected_s.split(",") if t.strip()}
        return actual_s.lower() in tokens
    if op == "not_in":
        tokens = {t.strip().lower() for t in expected_s.split(",") if t.strip()}
        return actual_s.lower() not in tokens
    if op in ("gt", "gte", "lt", "lte"):
        try:
            a, e = float(actual_s), float(expected_s)
        except (TypeError, ValueError):
            return False
        if op == "gt":
            return a > e
        if op == "gte":
            return a >= e
        if op == "lt":
            return a < e
        return a <= e
    return actual_s == expected_s
