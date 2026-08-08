"""Syscheck (File Integrity Monitoring) query service.

Powers the FIM dashboard (user/action/path breakdowns + timeline), the file
inventory and the paginated events table, all computed from the metadata DB.
"""

import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.models.syscheck import SyscheckAgent, SyscheckEvent, SyscheckFile

log = logging.getLogger("siem.syscheck")

USER_PALETTE = ["#1976D2", "#43A047", "#FB8C00", "#9E9E9E"]

ACTION_COLORS = {
    "deleted": "#E53935",
    "added": "#1976D2",
    "modified": "#FB8C00",
}

FILE_PALETTES = {
    "added": ["#1976D2", "#1E88E5", "#42A5F5", "#64B5F6", "#90CAF9"],
    "modified": ["#FB8C00", "#F57C00", "#FFA726", "#FFB74D", "#FFCC80"],
    "deleted": ["#E53935", "#D32F2F", "#EF5350", "#E57373", "#EF9A9A"],
}

SEVERITY_COLORS = {
    "critical": "#B71C1C",
    "high": "#E53935",
    "medium": "#FB8C00",
    "low": "#1976D2",
    "info": "#43A047",
}

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class SyscheckService:
    def __init__(self, db: Session) -> None:
        self.db = db

    # ------------------------------------------------------------ agents
    def agents(self) -> list[dict]:
        rows = self.db.execute(select(SyscheckAgent).order_by(SyscheckAgent.code)).scalars().all()
        demo = self._demo_flag()
        return [
            {
                "code": a.code,
                "name": a.name,
                "platform": a.platform,
                "os_name": a.os_name,
                "status": a.status,
                "registry_entries": a.registry_entries,
                "agent_id": a.id,
                "hostname": a.hostname,
                "ip_address": a.ip_address,
                "version": a.version,
                "last_seen": a.last_seen.isoformat() if a.last_seen else None,
                "enabled": a.enabled,
                "demo": demo,
            }
            for a in rows
        ]

    def _agent(self, agent_code: str) -> SyscheckAgent | None:
        return self.db.scalar(
            select(SyscheckAgent).where(SyscheckAgent.code == agent_code)
        )

    @staticmethod
    def _demo_flag() -> bool:
        from app.core.config import settings

        return bool(settings.fim_demo_mode)

    # ----------------------------------------------------------- summary
    def summary(self, agent_code: str = "001") -> dict:
        agent = self._agent(agent_code)
        if agent is None:
            return {
                "agent": None,
                "users": [],
                "actions": [],
                "files": {"added": [], "modified": [], "deleted": []},
                "files_count": {"total": 0, "active": 0, "deleted": 0},
                "events_total": 0,
                "severity": [],
            }

        user_rows = self.db.execute(
            select(SyscheckEvent.user, func.count(SyscheckEvent.id))
            .where(SyscheckEvent.agent_id == agent.id)
            .group_by(SyscheckEvent.user)
            .order_by(func.count(SyscheckEvent.id).desc())
            .limit(4)
        ).all()

        action_rows = self.db.execute(
            select(SyscheckEvent.event, func.count(SyscheckEvent.id))
            .where(SyscheckEvent.agent_id == agent.id)
            .group_by(SyscheckEvent.event)
        ).all()

        severity_rows = self.db.execute(
            select(SyscheckEvent.severity, func.count(SyscheckEvent.id))
            .where(SyscheckEvent.agent_id == agent.id)
            .group_by(SyscheckEvent.severity)
        ).all()
        severity = []
        for sev, count in severity_rows:
            key = (sev or "info").lower()
            severity.append(
                {"name": key, "value": count, "color": SEVERITY_COLORS.get(key, "#9E9E9E")}
            )
        severity.sort(key=lambda d: _SEVERITY_ORDER.get(d["name"], 9))

        files = {}
        for kind in ("added", "modified", "deleted"):
            rows = self.db.execute(
                select(SyscheckEvent.path, func.count(SyscheckEvent.id))
                .where(SyscheckEvent.agent_id == agent.id, SyscheckEvent.event == kind)
                .group_by(SyscheckEvent.path)
                .order_by(func.count(SyscheckEvent.id).desc())
                .limit(5)
            ).all()
            files[kind] = [
                {"name": path, "value": count, "color": FILE_PALETTES[kind][i]}
                for i, (path, count) in enumerate(rows)
            ]

        status_rows = self.db.execute(
            select(SyscheckFile.status, func.count(SyscheckFile.id))
            .where(SyscheckFile.agent_id == agent.id)
            .group_by(SyscheckFile.status)
        ).all()
        status_counts = {s or "unknown": c for s, c in status_rows}
        events_total = self.db.scalar(
            select(func.count())
            .select_from(SyscheckEvent)
            .where(SyscheckEvent.agent_id == agent.id)
        ) or 0

        return {
            "agent": {
                "code": agent.code,
                "name": agent.name,
                "platform": agent.platform,
                "os_name": agent.os_name,
                "status": agent.status,
                "registry_entries": agent.registry_entries,
                "agent_id": agent.id,
                "hostname": agent.hostname,
                "ip_address": agent.ip_address,
                "version": agent.version,
                "last_seen": agent.last_seen.isoformat() if agent.last_seen else None,
                "enabled": agent.enabled,
                "demo": self._demo_flag(),
            },
            "users": [
                {"name": name, "value": count, "color": USER_PALETTE[i]}
                for i, (name, count) in enumerate(user_rows)
            ],
            "actions": [
                {"name": kind, "value": count, "color": ACTION_COLORS.get(kind, "#9E9E9E")}
                for kind, count in action_rows
            ],
            "files": files,
            "files_count": {
                "total": sum(status_counts.values()),
                "active": status_counts.get("active", 0),
                "deleted": status_counts.get("deleted", 0),
            },
            "events_total": events_total,
            "severity": severity,
        }

    # ----------------------------------------------------------- timeline
    def timeline(
        self,
        hours: int = 24,
        bucket_minutes: int = 30,
        agent_code: str = "001",
    ) -> dict:
        agent = self._agent(agent_code)
        if agent is None:
            return {"interval_minutes": bucket_minutes, "points": []}

        step = bucket_minutes * 60
        now = _utcnow()
        start = now - timedelta(hours=hours)
        rows = self.db.execute(
            select(SyscheckEvent.timestamp, SyscheckEvent.event)
            .where(
                SyscheckEvent.agent_id == agent.id,
                SyscheckEvent.timestamp >= start,
                SyscheckEvent.timestamp <= now,
            )
        ).all()

        # SQLite stores naive datetimes even for tz-aware columns.
        anchor = start.replace(tzinfo=None)
        events = [(ts.replace(tzinfo=None), event) for ts, event in rows]

        points: list[dict] = []
        for slot in range(0, int(hours * 3600), step):
            bucket_start = anchor + timedelta(seconds=slot)
            bucket_end = bucket_start + timedelta(seconds=step)
            counts = {"deleted": 0, "added": 0, "modified": 0}
            for ts, event in events:
                if bucket_start <= ts < bucket_end:
                    counts[event] = counts.get(event, 0) + 1
            points.append(
                {
                    "label": f"{bucket_start.hour:02d}:{bucket_start.minute:02d}",
                    "deleted": counts["deleted"],
                    "added": counts["added"],
                    "modified": counts["modified"],
                }
            )
        return {"interval_minutes": bucket_minutes, "points": points}

    # ------------------------------------------------------------- files
    def files(self, agent_code: str = "001", search: str = "") -> list[dict]:
        agent = self._agent(agent_code)
        if agent is None:
            return []

        q = search.strip().lower()
        query = select(SyscheckFile).where(SyscheckFile.agent_id == agent.id)
        if q:
            query = query.where(
                or_(
                    SyscheckFile.file_path.ilike(f"%{q}%"),
                    SyscheckFile.user.ilike(f"%{q}%"),
                )
            )
        rows = self.db.execute(query.order_by(SyscheckFile.file_path)).scalars().all()
        return [
            {
                "file": f.file_path,
                "last_modified": f.last_modified.isoformat(),
                "user": f.user,
                "user_id": f.user_id,
                "size": f.size,
                "sha256": f.sha256,
                "owner": f.owner,
                "permissions": f.permissions,
                "file_type": f.file_type,
                "status": f.status,
                "first_seen": f.first_seen.isoformat() if f.first_seen else None,
                "last_seen": f.last_seen.isoformat() if f.last_seen else None,
                "demo": self._demo_flag(),
            }
            for f in rows
        ]

    # ------------------------------------------------------------ events
    def events(
        self,
        page: int = 1,
        per_page: int = 15,
        search: str = "",
        agent_code: str = "001",
    ) -> dict:
        agent = self._agent(agent_code)
        if agent is None:
            return {"items": [], "total": 0, "page": page, "perPage": per_page, "totalPages": 1}

        q = search.strip().lower()
        query = select(SyscheckEvent).where(SyscheckEvent.agent_id == agent.id)
        if q:
            query = query.where(
                or_(
                    SyscheckEvent.path.ilike(f"%{q}%"),
                    SyscheckEvent.event.ilike(f"%{q}%"),
                    SyscheckEvent.rule.ilike(f"%{q}%"),
                    SyscheckEvent.rule_id.ilike(f"%{q}%"),
                )
            )

        total = self.db.scalar(
            select(func.count()).select_from(query.subquery())
        ) or 0
        total_pages = max(1, -(-total // per_page))
        safe_page = min(max(1, page), total_pages)
        start = (safe_page - 1) * per_page

        rows = self.db.execute(
            query.order_by(SyscheckEvent.timestamp.desc(), SyscheckEvent.id.desc())
            .offset(start)
            .limit(per_page)
        ).scalars().all()

        return {
            "items": [
                {
                    "timestamp": e.timestamp.isoformat(),
                    "agent": agent.name,
                    "path": e.path,
                    "event": e.event,
                    "event_type": e.event_type or e.event,
                    "rule": e.rule,
                    "level": e.level,
                    "rule_id": e.rule_id,
                    "user": e.user,
                    "manager_name": e.manager_name,
                    "sha256": e.sha256,
                    "new_sha256": e.new_sha256,
                    "old_sha256": e.old_sha256,
                    "old_path": e.old_path,
                    "severity": e.severity,
                    "size": e.size,
                    "source": e.source,
                    "evidence": e.evidence,
                    "demo": self._demo_flag(),
                }
                for e in rows
            ],
            "total": total,
            "page": safe_page,
            "perPage": per_page,
            "totalPages": total_pages,
        }
