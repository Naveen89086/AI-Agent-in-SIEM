"""Detection rules endpoints (M8 backend support).

Exposes the correlation rules (Sigma-style YAML) and signature rules the
detection engines load, so the UI can show a Rules page with severity,
status and MITRE mapping.
"""

from pathlib import Path

from fastapi import APIRouter, Query

from app.api.deps import AnalystOrAdmin
from app.pipeline.rules import RuleSet
from app.pipeline.yara_matcher import build_signature_matcher

router = APIRouter()

RULES_DIR = Path(__file__).resolve().parents[2] / "rules"


def _rule_out(rule) -> dict:
    return {
        "id": rule.id,
        "title": rule.title,
        "description": rule.description,
        "severity": rule.severity,
        "status": rule.status,
        "condition": rule.condition,
        "threshold": rule.threshold,
        "timeframe_seconds": rule.timeframe_seconds,
        "group_by": rule.grouping_field,
        "logsource": rule.logsource,
        "mitre": rule.mitre,
        "tags": rule.tags,
        "source": rule.source,
    }


@router.get("", response_model=dict)
def list_rules(
    user: AnalystOrAdmin,
    severity: str | None = Query(default=None),
    status: str | None = Query(default=None),
    limit: int = Query(default=200, ge=1, le=1000),
) -> dict:
    rules = RuleSet.load_dir(RULES_DIR).rules
    signatures = build_signature_matcher().rules

    def _sig_out(rule) -> dict:
        return {
            "id": rule.id,
            "title": rule.title,
            "description": rule.description,
            "severity": rule.severity,
            "status": "active",
            "condition": "signature",
            "threshold": 1,
            "timeframe_seconds": None,
            "group_by": None,
            "logsource": {},
            "mitre": rule.mitre,
            "tags": rule.tags,
            "source": "signatures",
        }

    all_rules = [_rule_out(r) for r in rules] + [_sig_out(s) for s in signatures]
    if severity:
        all_rules = [r for r in all_rules if r["severity"] == severity]
    if status:
        all_rules = [r for r in all_rules if r["status"] == status]

    counts = {"correlation": len(rules), "signature": len(signatures)}
    for sev in ("informational", "low", "medium", "high", "critical"):
        counts[f"{sev}_count"] = sum(1 for r in all_rules if r["severity"] == sev)

    return {
        "items": all_rules[:limit],
        "total": len(all_rules),
        "counts": counts,
    }
