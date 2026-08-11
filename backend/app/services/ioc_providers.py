"""Online threat-intel providers (optional).

Every provider is opt-in (``THREAT_INTEL_ENABLED=true`` + an API key). Each one
must return an explicit verdict from the vendor; network failures or malformed
responses degrade to ``None`` which the caller reports as ``unknown``. None of
these providers ever returns a guessed verdict.
"""

import logging
from typing import Any

import httpx

from app.services.ioc_data import LookupResult

log = logging.getLogger("siem.ioc.providers")


class _BaseProvider:
    provider_name = "unknown"

    def __init__(self, api_key: str, timeout_seconds: float = 10.0) -> None:
        self.api_key = api_key
        self.timeout_seconds = timeout_seconds

    def _verdict(
        self,
        indicator_type: str,
        value: str,
        *,
        verdict: str,
        source: str,
        severity: str,
        threat: str | None,
        reference: str | None,
        confidence: float,
        detail: str | None = None,
    ) -> LookupResult:
        return LookupResult(
            verdict=verdict,
            indicator_type=indicator_type,
            value=value,
            source=source,
            severity=severity,
            threat=threat,
            reference=reference,
            confidence=confidence,
            detail=detail,
        )


class AbuseIPDBProvider(_BaseProvider):
    """AbuseIPDB v2 API - IPv4 reputation (85%+ confidence required)."""

    provider_name = "abuseipdb"

    async def lookup(self, indicator_type: str, value: str) -> LookupResult | None:
        if indicator_type != "ipv4":
            return None
        try:
            async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
                resp = await client.get(
                    "https://api.abuseipdb.com/api/v2/check",
                    headers={"Key": self.api_key, "Accept": "application/json"},
                    params={"ipAddress": value, "maxAgeInDays": 90},
                )
                resp.raise_for_status()
                data = resp.json().get("data", {})
        except Exception as exc:
            log.warning("AbuseIPDB lookup failed for %s: %s", value, exc)
            return None
        score = int(data.get("abuseConfidenceScore", 0) or 0)
        if score < 85:
            return None  # not confidently malicious; do not guess
        return self._verdict(
            indicator_type=indicator_type,
            value=value,
            verdict="malicious",
            source="abuseipdb",
            severity="high" if score >= 90 else "medium",
            threat=data.get("usageType") or "abuse.ip",
            reference=f"https://www.abuseipdb.com/check/{value}",
            confidence=score / 100.0,
            detail=f"abuseConfidenceScore={score}",
        )


class VirusTotalProvider(_BaseProvider):
    """VirusTotal v3 API - file hashes and IP/domain reputation."""

    provider_name = "virustotal"

    async def lookup(self, indicator_type: str, value: str) -> LookupResult | None:
        if indicator_type not in ("ipv4", "domain", "filehash"):
            return None
        kind = {"ipv4": "ip_addresses", "domain": "domains", "filehash": "files"}[indicator_type]
        url = f"https://www.virustotal.com/api/v3/{kind}/{value}"
        try:
            async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
                resp = await client.get(url, headers={"x-apikey": self.api_key})
                resp.raise_for_status()
                data = resp.json().get("data", {}).get("attributes", {})
        except Exception as exc:
            log.warning("VirusTotal lookup failed for %s: %s", value, exc)
            return None
        stats = data.get("last_analysis_stats", {})
        malicious = int(stats.get("malicious", 0) or 0)
        total = int(stats.get("total", 0) or 0)
        if malicious == 0:
            return None
        confidence = malicious / total if total else 0.0
        verdict = "malicious" if confidence >= 0.5 else "suspicious"
        return self._verdict(
            indicator_type=indicator_type,
            value=value,
            verdict=verdict,
            source="virustotal",
            severity="critical" if verdict == "malicious" and malicious >= 20 else "high",
            threat=data.get("meaningful_name") or data.get("reputation", "malicious"),
            reference=f"https://www.virustotal.com/gui/{'search' if indicator_type == 'filehash' else kind}/{value}",
            confidence=confidence,
            detail=f"malicious={malicious}/{total}",
        )


class OTXProvider(_BaseProvider):
    """AlienVault OTX - pulse indicator lookup."""

    provider_name = "otx"

    async def lookup(self, indicator_type: str, value: str) -> LookupResult | None:
        from urllib.parse import quote

        section = {
            "ipv4": "IPv4",
            "ipv6": "IPv6",
            "domain": "domain",
            "url": "url",
            "filehash": "file",
            "email": "email",
        }.get(indicator_type)
        if not section:
            return None
        url = f"https://otx.alienvault.com/api/v1/indicators/{section}/{quote(value)}/general"
        try:
            async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
                resp = await client.get(url, headers={"X-OTX-API-KEY": self.api_key})
                resp.raise_for_status()
                data = resp.json()
        except Exception as exc:
            log.warning("OTX lookup failed for %s: %s", value, exc)
            return None
        pulse_count = int(data.get("pulse_info", {}).get("count", 0) or 0)
        if pulse_count == 0:
            return None
        return self._verdict(
            indicator_type=indicator_type,
            value=value,
            verdict="malicious",
            source="otx",
            severity="high",
            threat=data.get("type_title") or "malicious.indicator",
            reference=f"https://otx.alienvault.com/indicator/{section}/{value}",
            confidence=min(1.0, 0.6 + pulse_count / 20),
            detail=f"pulses={pulse_count}",
        )


class GreyNoiseProvider(_BaseProvider):
    """GreyNoise community API - internet background noise classification."""

    provider_name = "greynoise"

    async def lookup(self, indicator_type: str, value: str) -> LookupResult | None:
        if indicator_type not in ("ipv4", "ipv6"):
            return None
        url = f"https://api.greynoise.io/v3/community/{value}"
        try:
            async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
                resp = await client.get(url, headers={"key": self.api_key})
                resp.raise_for_status()
                data = resp.json()
        except Exception as exc:
            log.warning("GreyNoise lookup failed for %s: %s", value, exc)
            return None
        classification = data.get("classification")
        if classification == "malicious":
            return self._verdict(
                indicator_type=indicator_type,
                value=value,
                verdict="malicious",
                source="greynoise",
                severity="high",
                threat=data.get("name") or "malicious.scanner",
                reference=f"https://viz.greynoise.io/ip/{value}",
                confidence=0.9,
                detail=f"first_seen={data.get('first_seen')} last_seen={data.get('last_seen')}",
            )
        if classification == "benign":
            return self._verdict(
                indicator_type=indicator_type,
                value=value,
                verdict="unknown",
                source="greynoise",
                severity="informational",
                threat="internet.noise",
                reference=f"https://viz.greynoise.io/ip/{value}",
                confidence=0.8,
                detail="classified as internet background noise",
            )
        return None


async def lookup_online(provider: Any, indicator_type: str, value: str) -> LookupResult | None:
    """Run one online lookup, swallowing provider errors as unknown."""
    try:
        return await provider.lookup(indicator_type, value)
    except Exception as exc:  # pragma: no cover - network resilience
        log.warning("Online lookup failed for %s %s: %s", indicator_type, value, exc)
        return None
