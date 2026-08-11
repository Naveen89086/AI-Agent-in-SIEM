"""Threat hunting service.

Loads built-in hunt definitions from ``data/hunts/*.yaml`` and executes them
against the log store (the same LogStore abstraction used by detection and
search). Every execution is persisted as a ``HuntQuery`` with the matched
events snapshotted as ``HuntResult`` rows, so the analyst gets a durable,
auditable history and a basis for AI analysis.

Hunt definitions use the ECS field vocabulary of the normalized event store:
``event.action``, ``event.category``, ``event.module``, ``process.name``,
``source.ip``, ``user.name``, etc.
"""

import json
import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.exceptions import NotFoundError, ValidationError
from app.models.hunting import HuntQuery, HuntResult
from app.storage.base import FilterField, SearchQuery, build_log_store

log = logging.getLogger("siem.hunt")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value) -> str | None:
    return value.isoformat() if value is not None else None


def _parse_json(value: str | None) -> Any:
    if not value:
        return None
    try:
        return json.loads(value)
    except (ValueError, TypeError):
        return value


def _load_hunt_definitions() -> list[dict[str, Any]]:
    """Load built-in hunt definitions from the hunts directory."""
    directory = Path(settings.hunts_dir)
    if not directory.exists():
        return []
    definitions: list[dict[str, Any]] = []
    for file in sorted(directory.glob("*.yml")) + sorted(directory.glob("*.yaml")):
        try:
            data = yaml.safe_load(file.read_text(encoding="utf-8"))
        except Exception:
            log.exception("Failed to parse hunt definition %s", file)
            continue
        if not isinstance(data, dict):
            continue
        data.setdefault("id", file.stem)
        data.setdefault("name", file.stem.replace("-", " ").title())
        data.setdefault("enabled", True)
        data.setdefault("severity", "medium")
        data.setdefault("mitre", [])
        data.setdefault("filters", [])
        data.setdefault("text", None)
        data.setdefault("threshold", None)
        data.setdefault("description", "")
        data["path"] = str(file)
        definitions.append(data)
    return definitions


class ThreatHuntingService:
    def __init__(self, db: Session) -> None:
        self.db = db

    # ================================================================ definitions
    def definitions(self) -> list[dict]:
        return [_definition_dict(d) for d in _load_hunt_definitions()]

    def definition(self, hunt_id: str) -> dict:
        for d in _load_hunt_definitions():
            if d.get("id") == hunt_id:
                return _definition_dict(d)
        raise NotFoundError(f"Hunt definition '{hunt_id}' not found")

    # =================================================================== history
    def queries(
        self,
        *,
        page: int = 1,
        per_page: int = 20,
        hunt_id: str | None = None,
    ) -> dict:
        query = select(HuntQuery)
        if hunt_id:
            query = query.where(HuntQuery.hunt_id == hunt_id)
        total = self.db.scalar(select(func.count()).select_from(query.subquery())) or 0
        total_pages = max(1, -(-total // per_page))
        safe_page = min(max(1, page), total_pages)
        rows = self.db.execute(
            query.order_by(HuntQuery.created_at.desc())
            .offset((safe_page - 1) * per_page)
            .limit(per_page)
        ).scalars().all()
        return {
            "items": [self._query_dict(q) for q in rows],
            "total": total,
            "page": safe_page,
            "perPage": per_page,
            "totalPages": total_pages,
            "demo": False,
        }

    def query_detail(self, query_id: str) -> dict:
        row = self.db.get(HuntQuery, query_id)
        if row is None:
            raise NotFoundError(f"Hunt query {query_id} not found")
        return self._query_dict(row)

    def query_results(
        self,
        *,
        query_id: str,
        page: int = 1,
        per_page: int = 20,
    ) -> dict:
        row = self.db.get(HuntQuery, query_id)
        if row is None:
            raise NotFoundError(f"Hunt query {query_id} not found")
        query = select(HuntResult).where(HuntResult.hunt_id == row.id)
        total = self.db.scalar(select(func.count()).select_from(query.subquery())) or 0
        total_pages = max(1, -(-total // per_page))
        safe_page = min(max(1, page), total_pages)
        rows = self.db.execute(
            query.order_by(HuntResult.timestamp.desc())
            .offset((safe_page - 1) * per_page)
            .limit(per_page)
        ).scalars().all()
        return {
            "items": [self._result_dict(r) for r in rows],
            "total": total,
            "page": safe_page,
            "perPage": per_page,
            "totalPages": total_pages,
        }

    # ==================================================================== execute
    async def run_hunt(
        self,
        *,
        hunt_id: str,
        time_from: datetime | None = None,
        time_to: datetime | None = None,
        created_by: str | None = None,
        limit: int = 100,
    ) -> dict:
        definition = self.definition(hunt_id)
        filters: list[FilterField] = []
        for f in definition.get("filters") or []:
            if isinstance(f, dict) and "field" in f:
                filters.append(FilterField(field=str(f["field"]), value=f.get("value")))

        record = HuntQuery(
            hunt_id=hunt_id,
            name=definition["name"],
            description=definition.get("description"),
            mitre_techniques=json.dumps(definition.get("mitre") or []),
            time_from=time_from,
            time_to=time_to,
            filters=json.dumps([{"field": f.field, "value": f.value} for f in filters])
            if filters
            else None,
            status="running",
            created_by=created_by,
            started_at=_now(),
        )
        self.db.add(record)
        self.db.commit()
        self.db.refresh(record)

        store = build_log_store()
        search_query = SearchQuery(
            text=definition.get("text"),
            filters=filters,
            time_from=time_from,
            time_to=time_to,
            size=limit,
        )
        try:
            response = await store.search(search_query)
        except Exception as exc:
            log.exception("Hunt '%s' search failed", hunt_id)
            record.status = "failed"
            record.error_message = str(exc)
            record.completed_at = _now()
            self.db.commit()
            return self._query_dict(record)

        for hit in response.hits:
            event = hit.source
            self.db.add(
                HuntResult(
                    hunt_id=record.id,
                    event_id=hit.id or str(event.get("event_id", "")),
                    timestamp=_parse_ts(event.get("@timestamp")),
                    host=_dig(event, "host.name"),
                    source_type=event.get("source_type"),
                    source_name=event.get("source_name"),
                    event_category=_category_of(event),
                    reason=definition["name"],
                    severity=definition.get("severity", "medium"),
                    event_fields=json.dumps(event, default=str)[:16000],
                )
            )

        record.matched_events = response.total
        record.status = "completed"
        record.completed_at = _now()
        record.result = json.dumps(self._summarize(response.hits), default=str)
        self.db.commit()
        return self._query_dict(record)

    # ================================================================== analysis
    async def analyze(self, query_id: str, *, force: bool = False) -> dict:
        row = self.db.get(HuntQuery, query_id)
        if row is None:
            raise NotFoundError(f"Hunt query {query_id} not found")
        if row.status != "completed":
            raise ValidationError("only completed hunts can be analyzed")

        from app.models.analysis import Analysis

        existing = self.db.scalar(
            select(Analysis).where(
                Analysis.kind == "hunt_analysis",
                Analysis.reference_id == query_id,
            )
        )
        if existing is not None and not force:
            return self._analysis_dict(existing)

        results = self.db.execute(
            select(HuntResult).where(HuntResult.hunt_id == row.id).order_by(HuntResult.timestamp.desc()).limit(50)
        ).scalars().all()
        result_dicts = [self._result_dict(r) for r in results]
        filters = _parse_json(row.filters) or []

        context = {
            "hunt_id": row.hunt_id,
            "name": row.name,
            "description": row.description,
            "mitre": _parse_json(row.mitre_techniques) or [],
            "filters": filters,
            "matched_events": row.matched_events,
            "time_from": _iso(row.time_from),
            "time_to": _iso(row.time_to),
            "results": result_dicts,
        }

        from app.agents import build_provider

        provider = build_provider()
        try:
            response = await provider.analyze_hunt(context)
        except Exception:
            log.exception("AI analyze_hunt failed; falling back to heuristic")
            from app.agents.heuristic import HeuristicProvider

            response = await HeuristicProvider().analyze_hunt(context)

        record = Analysis(
            kind="hunt_analysis",
            reference_id=query_id,
            provider=response.provider,
            prompt=json.dumps(context, default=str),
            analysis=response.analysis,
            summary=response.summary,
            recommended_actions=json.dumps(response.recommended_actions)
            if response.recommended_actions
            else None,
            risk_score=response.risk_score,
            confidence=response.confidence,
            response=json.dumps(response.extra, default=str) if response.extra else None,
        )
        self.db.add(record)
        self.db.commit()
        self.db.refresh(record)
        return self._analysis_dict(record)

    # ============================================================== serializers
    @staticmethod
    def _summarize(hits) -> dict:
        hosts: dict[str, int] = {}
        sources: dict[str, int] = {}
        for hit in hits:
            event = hit.source
            host = _dig(event, "host.name")
            if host:
                hosts[host] = hosts.get(host, 0) + 1
            src = event.get("source_type")
            if src:
                sources[src] = sources.get(src, 0) + 1
        return {
            "by_host": [{"key": k, "count": v} for k, v in sorted(hosts.items(), key=lambda kv: -kv[1])],
            "by_source_type": [{"key": k, "count": v} for k, v in sorted(sources.items(), key=lambda kv: -kv[1])],
        }

    def _query_dict(self, row: HuntQuery) -> dict:
        return {
            "id": row.id,
            "hunt_id": row.hunt_id,
            "name": row.name,
            "description": row.description,
            "mitre": _parse_json(row.mitre_techniques) or [],
            "time_from": _iso(row.time_from),
            "time_to": _iso(row.time_to),
            "filters": _parse_json(row.filters) or [],
            "status": row.status,
            "matched_events": row.matched_events,
            "created_by": row.created_by,
            "started_at": _iso(row.started_at),
            "completed_at": _iso(row.completed_at),
            "result": _parse_json(row.result),
            "error_message": row.error_message,
            "created_at": _iso(row.created_at),
        }

    def _result_dict(self, row: HuntResult) -> dict:
        return {
            "id": row.id,
            "hunt_id": row.hunt_id,
            "event_id": row.event_id,
            "timestamp": _iso(row.timestamp),
            "host": row.host,
            "source_type": row.source_type,
            "source_name": row.source_name,
            "event_category": row.event_category,
            "reason": row.reason,
            "severity": row.severity,
            "event": _parse_json(row.event_fields),
        }

    @staticmethod
    def _analysis_dict(record) -> dict:
        return {
            "id": record.id,
            "kind": record.kind,
            "reference_id": record.reference_id,
            "provider": record.provider,
            "analysis": record.analysis,
            "summary": record.summary,
            "recommended_actions": _parse_json(record.recommended_actions),
            "risk_score": record.risk_score,
            "confidence": record.confidence,
            "extra": _parse_json(record.response),
            "created_at": _iso(record.created_at),
        }


# --------------------------------------------------------------------- helpers
def _definition_dict(d: dict[str, Any]) -> dict:
    return {
        "id": d.get("id"),
        "name": d.get("name"),
        "description": d.get("description"),
        "enabled": d.get("enabled", True),
        "severity": d.get("severity", "medium"),
        "mitre": d.get("mitre") or [],
        "filters": d.get("filters") or [],
        "text": d.get("text"),
        "threshold": d.get("threshold"),
        "reference": d.get("reference"),
    }


def _dig(event: dict[str, Any], dotted: str) -> Any:
    node: Any = event
    for part in dotted.split("."):
        if isinstance(node, dict) and part in node:
            node = node[part]
        else:
            return None
    return node


def _parse_ts(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed
    except ValueError:
        return None


def _category_of(event: dict[str, Any]) -> str | None:
    cats = _dig(event, "event.category") or []
    if isinstance(cats, list) and cats:
        return str(cats[0])
    if isinstance(cats, str):
        return cats
    return None
