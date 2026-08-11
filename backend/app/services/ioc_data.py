"""IOC corpus loader and lookup logic.

The offline list (``data/ioc/iocs.yaml``) is the default threat-intelligence
source. Lookups are deliberately conservative and honest:

- A value that matches an active offline entry returns ``malicious`` (or the
  entry's severity) with a real ``source``, ``threat`` and ``reference``.
- A value that matches nothing returns ``unknown`` - it is never reported as
  clean because "not in our list" is not proof of safety.
- Online providers (AbuseIPDB, VirusTotal, OTX, GreyNoise) are only queried
  when ``THREAT_INTEL_ENABLED=true`` and the API key is configured. Provider
  failures degrade to ``unknown`` with an explanatory detail, never to a
  fabricated verdict.
"""

import ipaddress
import logging
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from app.core.config import settings

log = logging.getLogger("siem.ioc.data")


class LookupResult:
    """A lookup outcome with an explicit verdict."""

    def __init__(
        self,
        *,
        verdict: str,
        indicator_type: str,
        value: str,
        source: str,
        severity: str = "unknown",
        threat: str | None = None,
        reference: str | None = None,
        confidence: float = 0.0,
        detail: str | None = None,
    ) -> None:
        self.verdict = verdict  # malicious | suspicious | unknown
        self.indicator_type = indicator_type
        self.value = value
        self.source = source
        self.severity = severity
        self.threat = threat
        self.reference = reference
        self.confidence = confidence
        self.detail = detail

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict,
            "type": self.indicator_type,
            "value": self.value,
            "source": self.source,
            "severity": self.severity,
            "threat": self.threat,
            "reference": self.reference,
            "confidence": round(self.confidence, 2),
            "detail": self.detail,
        }


def canonical_value(indicator_type: str, value: str) -> str:
    """Normalize an indicator for matching (case-insensitive where sensible)."""
    value = (value or "").strip()
    if indicator_type in ("domain", "url", "email", "registry"):
        return value.lower()
    if indicator_type == "ipv4":
        try:
            return str(ipaddress.IPv4Address(value))
        except ipaddress.AddressValueError:
            return value
    if indicator_type == "ipv6":
        try:
            return str(ipaddress.IPv6Address(value))
        except ipaddress.AddressValueError:
            return value
    if indicator_type == "filehash":
        return value.lower()
    return value


def _load_file(path: str) -> list[dict[str, Any]]:
    p = Path(path)
    if not p.exists():
        log.warning("IOC list not found at %s; using empty corpus", path)
        return []
    try:
        data = yaml.safe_load(p.read_text(encoding="utf-8"))
    except Exception:
        log.exception("Failed to parse IOC list %s", path)
        return []
    if not isinstance(data, list):
        log.warning("IOC list %s is not a list", path)
        return []
    return data


@lru_cache(maxsize=1)
def _offline_entries() -> list[dict[str, Any]]:
    return _load_file(settings.ioc_list_path)


def offline_indicators() -> list[dict[str, Any]]:
    """The active offline indicators (list of normalized dicts)."""
    from datetime import datetime, timezone

    now = datetime.now(timezone.utc)
    out: list[dict[str, Any]] = []
    for entry in _offline_entries():
        expires = entry.get("expires_at")
        if expires:
            try:
                exp_dt = datetime.fromisoformat(str(expires).replace("Z", "+00:00"))
                if exp_dt <= now:
                    continue
            except ValueError:
                pass
        out.append(
            {
                "id": f"offline:{canonical_value(str(entry.get('type', '')), str(entry.get('value', '')))}",
                "indicator_type": str(entry.get("type", "unknown")),
                "value": canonical_value(str(entry.get("type", "")), str(entry.get("value", ""))),
                "source": str(entry.get("source", "bundled")),
                "threat": entry.get("threat"),
                "severity": str(entry.get("severity", "medium")),
                "tags": entry.get("tags") or [],
                "reference": entry.get("reference"),
                "active": True,
            }
        )
    return out


def lookup_offline(indicator_type: str, value: str) -> LookupResult | None:
    """Match a value against the bundled offline corpus, or None when unknown."""
    key = canonical_value(indicator_type, value)
    for entry in _offline_entries():
        if canonical_value(str(entry.get("type", "")), str(entry.get("value", ""))) != key:
            continue
        return LookupResult(
            verdict="malicious",
            indicator_type=indicator_type,
            value=value,
            source=str(entry.get("source", "bundled")),
            severity=str(entry.get("severity", "medium")),
            threat=entry.get("threat"),
            reference=entry.get("reference"),
            confidence=0.95,
        )
    return None


# --------------------------------------------------------------------- online
class ThreatIntelProvider:
    """Optional online reputation provider. Never fabricates verdicts."""

    provider_name = "unknown"

    async def lookup(self, indicator_type: str, value: str) -> LookupResult | None:
        return None


def build_threat_intel() -> ThreatIntelProvider | None:
    """Return the configured online provider, or None when disabled."""
    if not settings.threat_intel_enabled or not settings.threat_intel_api_key:
        return None
    try:
        if settings.threat_intel_provider == "abuseipdb":
            from app.services.ioc_providers import AbuseIPDBProvider

            return AbuseIPDBProvider(settings.threat_intel_api_key, settings.threat_intel_timeout_seconds)
        if settings.threat_intel_provider == "virustotal":
            from app.services.ioc_providers import VirusTotalProvider

            return VirusTotalProvider(settings.threat_intel_api_key, settings.threat_intel_timeout_seconds)
        if settings.threat_intel_provider == "otx":
            from app.services.ioc_providers import OTXProvider

            return OTXProvider(settings.threat_intel_api_key, settings.threat_intel_timeout_seconds)
        if settings.threat_intel_provider == "greynoise":
            from app.services.ioc_providers import GreyNoiseProvider

            return GreyNoiseProvider(settings.threat_intel_api_key, settings.threat_intel_timeout_seconds)
    except ImportError:
        log.exception("Threat-intel provider import failed")
    return None
