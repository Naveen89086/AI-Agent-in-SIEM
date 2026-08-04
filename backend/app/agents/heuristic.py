"""Offline heuristic AI analyst (function 6).

Runs without any API keys or network access. Combines deterministic scoring,
an embedded MITRE ATT&CK reference and remediation playbooks so the platform
is fully functional out of the box; remote LLMs (M6 llm_provider) layer on top.
"""

import logging
from datetime import datetime, timezone
from typing import Any

from app.agents.base import AgentProvider, AgentResponse

log = logging.getLogger("siem.agent.heuristic")

# ------------------------------------------------------------------------- MITRE
# Reference: technique_id -> (description, remediation bullets)
_MITRE = {
    "T1003": ("OS Credential Dumping", "Extract hashes/secrets from memory or LSA. Remediation: kill offending processes, rotate credentials, enable Credential Guard, restrict debug privilege."),
    "T1059": ("Command and Scripting Interpreter", "Attackers execute code via shells/script engines. Remediation: constrain script execution, review policy allow-lists, block unsigned scripts."),
    "T1059.001": ("PowerShell", "Malicious PowerShell usage. Remediation: Constrained Language Mode, logging, block EncodedCommand, review script blocks."),
    "T1027": ("Obfuscated Files or Information", "Payload hidden via encoding/encryption. Remediation: inspect encoded payloads, tighten AV/EDR detections, sandbox unknown files."),
    "T1046": ("Network Service Discovery", "Port/service scanning to map the network. Remediation: block scanning sources, restrict inbound exposure, use host firewalls."),
    "T1047": ("Windows Management Instrumentation", "WMI used for lateral movement / execution. Remediation: restrict WMI access, monitor WMI event subscriptions, disable unnecessary RPC/WMI."),
    "T1070": ("Indicator Removal on Host", "Log clearing / artifact deletion to evade forensics. Remediation: harden log tampering, forward logs off-host, verify audit integrity."),
    "T1070.001": ("Clear Windows Event Logs", "Security log cleared (event 1102). Remediation: verify logging pipeline, restore off-host copies, investigate who cleared logs."),
    "T1078": ("Valid Accounts", "Use of legitimate credentials. Remediation: revoke creds, enforce MFA, check for password reuse, review access."),
    "T1110": ("Brute Force", "Guessing/spraying passwords. Remediation: account lockout, MFA, block source IPs, rate-limit authentication."),
    "T1110.003": ("Password Spraying", "One password across many accounts. Remediation: MFA, lockout policies, threat-intel blocklists, review logins."),
    "T1136": ("Create Account", "Rogue account creation for persistence. Remediation: verify account against change tickets, disable unknown accounts, audit IAM."),
    "T1486": ("Data Encrypted for Impact", "Ransomware-style file encryption. Remediation: contain host immediately, block C2, restore from backups, preserve evidence."),
    "T1548": ("Abuse Elevation Control Mechanism", "Exploiting sudo/UAC for privilege elevation. Remediation: restrict sudo to least privilege, audit elevation, monitor unusual commands."),
    "T1547": ("Boot or Logon Autostart Execution", "Persistence via autostart locations. Remediation: audit run keys/services, remove unknown entries, monitor registry changes."),
}

_SEVERITY_RISK = {"informational": 1.0, "low": 2.5, "medium": 5.0, "high": 7.5, "critical": 9.5}
_CONFIDENCE = {"correlation": 0.85, "signature": 0.9, "yara": 0.9, "ml": 0.6, "sigma": 0.85}

# ------------------------------------------------------------------- analysis
def _mitre_entries(alert: dict[str, Any]) -> list[dict[str, str]]:
    raw = alert.get("mitre") or []
    if not isinstance(raw, list):
        return []
    entries = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        technique = str(item.get("technique", "")).split(".")[0]
        info = _MITRE.get(technique)
        entries.append(
            {
                "tactic": str(item.get("tactic", "")),
                "technique": technique,
                "technique_name": str(item.get("technique_name") or (info[0] if info else "")),
                "description": info[1].split(".")[0] if info else "",
            }
        )
    return entries


def _recommendations(alert: dict[str, Any]) -> list[str]:
    mitre = alert.get("mitre") or []
    actions: list[str] = []
    techniques = {str(m.get("technique", "")).split(".")[0] for m in mitre if isinstance(m, dict)}
    for technique in sorted(techniques):
        info = _MITRE.get(technique)
        if info:
            actions.append(f"[{technique}] {info[1]}")
    severity = str(alert.get("severity", "medium")).lower()
    if severity in ("high", "critical"):
        actions.insert(0, "Contain immediately: isolate affected host(s) and block attacker IP(s) at the firewall.")
    actions.insert(0, f"Triangulate with the grouped indicators (source: {_group_value(alert)}).")
    return _dedupe(actions)[:6]


def _group_value(alert: dict[str, Any]) -> str:
    grouping = alert.get("grouping") or {}
    if isinstance(grouping, dict):
        return ", ".join(f"{k}={v}" for k, v in grouping.items())
    return str(grouping)


def _dedupe(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


# ------------------------------------------------------------------- provider
class HeuristicProvider(AgentProvider):
    provider_name = "heuristic"

    async def analyze_alert(self, alert: dict[str, Any]) -> AgentResponse:
        title = alert.get("rule_title", "Unknown alert")
        severity = str(alert.get("severity", "medium")).lower()
        detector = alert.get("detector", "correlation")
        count = int(alert.get("count", 1))
        mitre = _mitre_entries(alert)

        base_risk = _SEVERITY_RISK.get(severity, 5.0)
        risk = min(10.0, base_risk + min(count - 1, 5) * 0.4)
        confidence = _CONFIDENCE.get(detector, 0.7)

        narrative = [
            f"Alert '{title}' (severity: {severity}) was raised by the {detector} detector and has occurred {count} time(s).",
        ]
        if mitre:
            tactics = ", ".join(sorted({m["tactic"] for m in mitre if m["tactic"]}))
            narrative.append(
                f"It maps to the MITRE ATT&CK technique(s) {', '.join(m['technique'] for m in mitre)} "
                f"under the {tactics} tactic(s), indicating the phase of the attack chain being observed."
            )
        else:
            narrative.append(
                "No explicit MITRE mapping was provided, so this may be a custom or ML-derived signal."
            )
        if severity in ("high", "critical"):
            narrative.append(
                "Given the severity, treat this as a probable active incident and escalate for immediate review."
            )

        return AgentResponse(
            analysis=" ".join(narrative),
            summary=f"{title} — {severity} severity, {count} occurrence(s), {detector} detector.",
            mitre=mitre,
            recommended_actions=_recommendations(alert),
            risk_score=round(risk, 1),
            confidence=round(confidence, 2),
            provider=self.provider_name,
            extra={"detector": detector, "count": count},
        )

    async def summarize_incident(
        self, alerts: list[dict[str, Any]], context: str = ""
    ) -> AgentResponse:
        if not alerts:
            return AgentResponse(
                analysis="No alerts were provided for this incident.",
                provider=self.provider_name,
            )
        severities = [str(a.get("severity", "medium")).lower() for a in alerts]
        worst = max(severities, key=lambda s: _SEVERITY_RISK.get(s, 0))
        sources: set[str] = set()
        rules: set[str] = set()
        total_occurrences = 0
        for alert in alerts:
            total_occurrences += int(alert.get("count", 1))
            rules.add(str(alert.get("rule_title", "?")))
            grouping = alert.get("grouping") or {}
            if isinstance(grouping, dict):
                for value in grouping.values():
                    sources.add(str(value))

        lines = [
            f"This incident spans {len(alerts)} distinct alert(s) totaling {total_occurrences} raw occurrence(s).",
            f"The highest severity is '{worst}'.",
            "Involved rules: " + "; ".join(sorted(rules)) + ".",
        ]
        if sources:
            lines.append("Key involved values/indicators: " + ", ".join(sorted(sources)) + ".")
        if context:
            lines.append("Analyst context: " + context)
        recommended: list[str] = []
        for alert in alerts:
            recommended.extend(_recommendations(alert))
        recommended = _dedupe(recommended)[:6]

        return AgentResponse(
            analysis=" ".join(lines),
            summary=f"Incident with {len(alerts)} alert(s), worst severity '{worst}'.",
            mitre=_merge_mitre(alerts),
            recommended_actions=recommended,
            risk_score=round(_SEVERITY_RISK.get(worst, 5.0), 1),
            confidence=0.75,
            provider=self.provider_name,
        )

    async def chat(self, prompt: str, context: dict[str, Any] | None = None) -> str:
        lowered = prompt.lower()
        if context and context.get("alert"):
            alert = context["alert"]
            analysis = await self.analyze_alert(alert)
            if "what is" in lowered or "explain" in lowered or "analy" in lowered:
                return analysis.analysis + "\n\nRecommended actions:\n- " + "\n- ".join(analysis.recommended_actions)
        if "recommend" in lowered or "action" in lowered or "remediat" in lowered or "mitigat" in lowered:
            return "General hardening guidance: enable MFA everywhere, apply least-privilege RBAC, keep hosts patched, forward logs to a tamper-proof store, and block high-risk source IPs at the perimeter."
        if "mitre" in lowered or "att&ck" in lowered or "tactic" in lowered:
            return "MITRE ATT&CK is a knowledge base of adversary tactics/techniques. Analysts use it to classify detection coverage and map alerts to attack phases (Initial Access → Execution → Persistence → Privilege Escalation → Defense Evasion → Credential Access → Discovery → Lateral Movement → Collection → Command & Control → Exfiltration → Impact)."
        if "report" in lowered or "summar" in lowered:
            return "Use the incident summary feature to auto-generate a narrative of all correlated alerts; then export a compliance report (NIST/CIS/GDPR) from the reporting module."
        if "block" in lowered or "isolate" in lowered or "playbook" in lowered:
            return "Automated response is available via SOAR playbooks (block IP, isolate host, kill process). Review the action's blast radius before enabling in production."
        return (
            "I am the SIEM analyst assistant. I can explain alerts, map them to MITRE ATT&CK, "
            "recommend remediation, and summarize incidents. Ask e.g. 'explain the latest SSH brute "
            "force alert' or 'what should I do about a ransomware hash match?'"
        )


def _merge_mitre(alerts: list[dict[str, Any]]) -> list[dict[str, str]]:
    merged: dict[str, dict[str, str]] = {}
    for alert in alerts:
        for entry in _mitre_entries(alert):
            merged.setdefault(entry["technique"], entry)
    return list(merged.values())
