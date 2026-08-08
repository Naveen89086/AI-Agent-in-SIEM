"""SCA - deterministic rule evaluator tests."""

from app.sca.evaluator import apply_operator, normalize


def test_equals_case_insensitive():
    assert apply_operator("eq", " Enabled ", "enabled") is True
    assert apply_operator("equal", "enabled", "enabled") is True
    assert apply_operator("=", "enabled", "enabled") is True
    assert apply_operator("==", "enabled", "enabled") is True


def test_not_equals():
    assert apply_operator("neq", "disabled", "enabled") is True
    assert apply_operator("!=", "disabled", "enabled") is True
    assert apply_operator("neq", "disabled", "disabled") is False


def test_truthy_falsy_semantics():
    for value in ("yes", "true", "enabled", "1", "present"):
        assert apply_operator("eq", value, "enabled") is True
    for value in ("no", "false", "disabled", "0", "absent", "none"):
        assert apply_operator("eq", value, "enabled") is False


def test_falsy_expected_matches_absent():
    assert apply_operator("eq", "", "disabled") is True
    assert apply_operator("eq", "absent", "disabled") is True
    assert apply_operator("eq", "enabled", "disabled") is False


def test_contains_family():
    assert apply_operator("contains", "Audit Account Logon: Success", "account logon") is True
    assert apply_operator("contain", "Audit Account Logon", "account logon") is True
    assert apply_operator("contains", "Audit Logon", "account logon") is False
    assert apply_operator("not_contains", "Audit Logon", "account logon") is True
    assert apply_operator("startswith", "AuditLogon", "audit") is True
    assert apply_operator("endswith", "LogonEvent", "event") is True


def test_in_list_family():
    assert apply_operator("in", "medium", "low,medium,high") is True
    assert apply_operator("in_list", "High", "low,medium,high") is True
    assert apply_operator("in", "critical", "low,medium,high") is False
    assert apply_operator("not_in", "critical", "low,medium,high") is True


def test_numeric_comparisons():
    assert apply_operator("gt", "42", "7") is True
    assert apply_operator("gte", "7", "7") is True
    assert apply_operator("lt", "3", "7") is True
    assert apply_operator("lte", "7", "7") is True
    assert apply_operator(">", "42", "7") is True
    assert apply_operator("gt", "abc", "7") is False


def test_regex_operator():
    assert apply_operator("regex", "ERROR code 42", r"code \d+") is True
    assert apply_operator("regex_match", "no match here", r"code \d+") is False
    assert apply_operator("regex", "abc", "[invalid") is False


def test_exists_operators():
    assert apply_operator("exists", "value", "present") is True
    assert apply_operator("exists", "", "present") is False
    assert apply_operator("not_exists", "", "present") is True
    assert apply_operator("not_exists", "value", "present") is False


def test_unknown_operator_falls_back_to_equality():
    assert apply_operator("mystery", "enabled", "enabled") is True
    assert apply_operator("mystery", "disabled", "enabled") is False


def test_normalize_handles_none_and_whitespace():
    assert normalize(None) == ""
    assert normalize(42) == "42"
    assert normalize("  x  ") == "x"
