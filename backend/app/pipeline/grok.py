"""Grok-style pattern engine.

A lightweight reimplementation of Logstash-style Grok: named patterns are
compiled into a single regular expression with named groups. Supports
custom user patterns merged over the built-in library.

Pattern syntax:  %{PATTERN_NAME:field_name}
"""

import re
from dataclasses import dataclass, field
from typing import Any


# ---------------------------------------------------------------------------
# Built-in pattern library (a practical subset of grok-patterns)
# ---------------------------------------------------------------------------
def _ipv4() -> str:
    return r"(?:[0-9]{1,3}\.){3}[0-9]{1,3}"


def _ipv6() -> str:
    return r"(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}|:(?::[0-9a-fA-F]{1,4}){1,7}|::"


BASE_PATTERNS: dict[str, str] = {
    "WORD": r"\b\w+\b",
    "NOTSPACE": r"\S+",
    "SPACE": r"\s+",
    "INT": r"[+-]?[0-9]+",
    "NUMBER": r"[+-]?(?:[0-9]+(?:\.[0-9]+)?)|\.[0-9]+",
    "BASE16NUM": r"(?:0x)?[0-9a-fA-F]+",
    "POSINT": r"\b[0-9]+\b",
    "IPV4": _ipv4(),
    "IPV6": _ipv6(),
    "IP": _ipv4() + r"|" + _ipv6(),
    "HOSTNAME": r"\b(?:[0-9A-Za-z](?:[-0-9A-Za-z]{0,61}[0-9A-Za-z])?\.)+[A-Za-z]{2,63}\b|\b[0-9A-Za-z][-0-9A-Za-z]*\b",
    "HOSTPORT": r"(?:[0-9A-Za-z][-0-9A-Za-z.]*:[0-9]+)",
    "MAC": r"(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}",
    "PATH": r"(?:/|\\|\./)[\w\.\/\\\-: ]+",
    "DATA": r".*?",
    "GREEDYDATA": r".*",
    "TIMESTAMP_ISO8601": r"%{YEAR}-%{MONTHNUM}-%{MONTHDAY}[T ]%{HOUR}:?%{MINUTE}(?::?%{SECOND})?%{ISO8601_TIMEZONE}?",
    "SYSLOGTIMESTAMP": r"%{MONTH} +%{MONTHDAY} %{TIME}",
    "ISO8601_TIMEZONE": r"Z|[+-]%{HOUR}(?::?%{MINUTE})?",
    "YEAR": r"\d{4}",
    "MONTHNUM": r"0?[1-9]|1[0-2]",
    "MONTHDAY": r"(?:0[1-9]|(?:[12][0-9]|3[0-1]))",
    "MONTH": r"Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?",
    "HOUR": r"2[0123]|[01]?[0-9]",
    "MINUTE": r"[0-5][0-9]",
    "SECOND": r"(?:[0-5][0-9]|60)(?:[:.,][0-9]+)?",
    "TIME": r"%{HOUR}:%{MINUTE}(?::%{SECOND})?",
    "UUID": r"\b[A-Fa-f0-9]{8}-(?:[A-Fa-f0-9]{4}-){3}[A-Fa-f0-9]{12}\b",
    "EMAILADDRESS": r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}",
    "USERNAME": r"[a-zA-Z0-9._-]+",
    "URIPATHPARAM": r"[A-Za-z0-9_\-\.\/\?=&]+",
    "COMMONAPACHELOG": r"%{IPORHOST:clientip} %{USER:ident} %{USER:auth} \[%{HTTPDATE:timestamp}\] \"%{WORD:verb} %{URIPATHPARAM:request} HTTP/%{NUMBER:httpversion}\" %{NUMBER:response} (?:%{NUMBER:bytes}|-)",
    "HTTPDATE": r"%{MONTHDAY}/%{MONTH}/%{YEAR}:%{TIME} %{INT}",
    "IPORHOST": r"%{IP}|%{HOSTNAME}",
    "USER": r"[a-zA-Z0-9._-]+",
    "QS": r'"(?:[^"\\]|\\.)*"',
}


# ---------------------------------------------------------------------------
# Grok
# ---------------------------------------------------------------------------
@dataclass
class GrokMatch:
    fields: dict[str, Any] = field(default_factory=dict)
    remainder: str = ""


class Grok:
    """Compiles a Grok expression into a regex and matches strings against it."""

    def __init__(
        self,
        expression: str,
        patterns: dict[str, str] | None = None,
        anchors: bool = True,
    ) -> None:
        merged = dict(BASE_PATTERNS)
        if patterns:
            merged.update(patterns)
        self.patterns = merged
        self.expression = expression
        self._compiled: dict[tuple[bool, bool], re.Pattern] = {}
        self._resolve()

    def _resolve(self) -> None:
        """Expand nested %{...} references until stable."""
        expression = self.expression
        prev = None
        guard = 0
        while prev != expression and guard < 50:
            prev = expression
            expression = re.sub(
                r"%\{([A-Z0-9_]+)(?::([a-zA-Z0-9_.]+))?\}",
                self._expand,
                expression,
            )
            guard += 1
        self._expanded = expression

    def _expand(self, match: re.Match) -> str:
        name = match.group(1)
        field = match.group(2) if match.lastindex is not None and match.lastindex >= 2 else None
        pattern = self.patterns.get(name)
        if pattern is None:
            return match.group(0)
        inner = self._flatten(pattern)
        if field:
            return f"(?P<{field}>{inner})"
        return f"(?:{inner})"

    def _flatten(self, pattern: str) -> str:
        def repl(m: re.Match) -> str:
            name = m.group(1)
            return f"(?:{self.patterns.get(name, m.group(0))})"

        prev, guard = None, 0
        while prev != pattern and guard < 50:
            prev = pattern
            pattern = re.sub(r"%\{([A-Z0-9_]+)\}", repl, pattern)
            guard += 1
        return pattern

    def match(self, text: str, *, full: bool = True) -> GrokMatch | None:
        key = (full, False)
        if key not in self._compiled:
            pattern = self._expanded
            if full:
                pattern = f"^{pattern}$"
            self._compiled[key] = re.compile(pattern)
        compiled = self._compiled[key]

        m = compiled.search(text)
        if not m:
            return None
        fields: dict[str, Any] = {}
        for name, value in m.groupdict().items():
            if value is not None:
                fields[name] = value
        remainder = text
        if m.span() and not full:
            start, end = m.span()
            remainder = text[:start] + text[end:]
        return GrokMatch(fields=fields, remainder=remainder)

    def compile_regex(self) -> re.Pattern:
        return re.compile(f"^{self._expanded}$")


def cast_value(value: str) -> Any:
    """Best-effort type casting for grok capture groups."""
    if value is None:
        return None
    try:
        if re.fullmatch(r"[+-]?\d+", value):
            return int(value)
        if re.fullmatch(r"[+-]?\d+\.\d+", value):
            return float(value)
    except ValueError:
        pass
    if value in ("true", "false"):
        return value == "true"
    if value == "-":
        return None
    return value
