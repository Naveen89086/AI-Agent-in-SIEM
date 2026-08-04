"""Investigation case service (function 7)."""

import json
from datetime import datetime, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.exceptions import NotFoundError, ValidationError
from app.models.alert import Alert
from app.models.case import Case, CaseArtifact, CaseNote, CaseStatus
from app.schemas.case import CaseArtifactCreate, CaseCreate, CaseNoteCreate, CaseUpdate


def _dumps(value) -> str | None:
    return json.dumps(value) if value is not None else None


class CaseService:
    def __init__(self, db: Session) -> None:
        self.db = db

    # ------------------------------------------------------------------- CRUD
    def create(self, data: CaseCreate, author: str = "analyst") -> Case:
        case = Case(
            title=data.title,
            description=data.description,
            severity=data.severity,
            assignee=data.assignee,
            tags=_dumps(data.tags or None),
            alert_ids=_dumps(data.alert_ids or None),
            opened_at=datetime.now(timezone.utc),
        )
        self.db.add(case)
        self.db.flush()
        if data.description:
            self.db.add(
                CaseNote(case_id=case.id, author=author, content=f"Case opened: {data.description}")
            )
        self.db.commit()
        self.db.refresh(case)
        return case

    def get(self, case_id: str) -> Case:
        case = self.db.get(Case, case_id)
        if case is None:
            raise NotFoundError(f"Case {case_id} not found")
        return case

    def list_cases(
        self,
        *,
        status: str | None = None,
        severity: str | None = None,
        assignee: str | None = None,
        offset: int = 0,
        limit: int = 50,
    ) -> tuple[list[Case], int]:
        query = select(Case)
        count_query = select(func.count(Case.id))
        if status:
            query = query.where(Case.status == status)
            count_query = count_query.where(Case.status == status)
        if severity:
            query = query.where(Case.severity == severity)
            count_query = count_query.where(Case.severity == severity)
        if assignee:
            query = query.where(Case.assignee == assignee)
            count_query = count_query.where(Case.assignee == assignee)
        total = self.db.scalar(count_query) or 0
        rows = list(
            self.db.scalars(query.order_by(Case.updated_at.desc()).offset(offset).limit(limit)).all()
        )
        return rows, total

    def update(self, case_id: str, data: CaseUpdate, author: str = "analyst") -> Case:
        case = self.get(case_id)
        changed: list[str] = []
        for field_name in ("title", "description", "severity", "assignee"):
            value = getattr(data, field_name)
            if value is not None:
                setattr(case, field_name, value)
                changed.append(field_name)
        if data.status is not None:
            case.status = data.status
            changed.append("status")
            if data.status == CaseStatus.CLOSED:
                case.closed_at = datetime.now(timezone.utc)
            elif data.status != CaseStatus.CLOSED:
                case.closed_at = None
        if data.tags is not None:
            case.tags = _dumps(data.tags)
        if data.alert_ids is not None:
            case.alert_ids = _dumps(data.alert_ids)
        if changed:
            self.db.add(
                CaseNote(case_id=case.id, author=author, content=f"Updated: {', '.join(changed)}")
            )
        self.db.commit()
        self.db.refresh(case)
        return case

    def delete(self, case_id: str) -> None:
        case = self.get(case_id)
        self.db.delete(case)
        self.db.commit()

    # ------------------------------------------------------------------ notes
    def add_note(self, case_id: str, data: CaseNoteCreate, author: str = "analyst") -> CaseNote:
        self.get(case_id)
        note = CaseNote(case_id=case_id, author=author, content=data.content)
        self.db.add(note)
        self.db.commit()
        self.db.refresh(note)
        return note

    def list_notes(self, case_id: str) -> list[CaseNote]:
        self.get(case_id)
        return list(
            self.db.scalars(
                select(CaseNote).where(CaseNote.case_id == case_id).order_by(CaseNote.created_at)
            ).all()
        )

    # -------------------------------------------------------------- artifacts
    def add_artifact(self, case_id: str, data: CaseArtifactCreate) -> CaseArtifact:
        self.get(case_id)
        artifact = CaseArtifact(
            case_id=case_id,
            artifact_type=data.artifact_type,
            value=data.value,
            source=data.source,
            note=data.note,
        )
        self.db.add(artifact)
        self.db.commit()
        self.db.refresh(artifact)
        return artifact

    def list_artifacts(self, case_id: str) -> list[CaseArtifact]:
        self.get(case_id)
        return list(
            self.db.scalars(
                select(CaseArtifact)
                .where(CaseArtifact.case_id == case_id)
                .order_by(CaseArtifact.created_at)
            ).all()
        )

    # --------------------------------------------------------------- timeline
    def timeline(self, case_id: str) -> list[dict]:
        """Chronological merge of notes, artifacts and linked alert activity."""
        case = self.get(case_id)
        entries: list[dict] = [
            {
                "at": case.opened_at,
                "type": "case_opened",
                "title": f"Case '{case.title}' opened",
                "detail": case.description or "",
            }
        ]
        for note in self.list_notes(case_id):
            entries.append(
                {
                    "at": note.created_at,
                    "type": "note",
                    "title": f"Note by {note.author}",
                    "detail": note.content,
                }
            )
        for artifact in self.list_artifacts(case_id):
            entries.append(
                {
                    "at": artifact.created_at,
                    "type": "artifact",
                    "title": f"Artifact {artifact.artifact_type}: {artifact.value}",
                    "detail": artifact.note or "",
                }
            )
        alert_ids = _load(case.alert_ids) or []
        for alert_id in alert_ids:
            alert = self.db.get(Alert, alert_id)
            if alert is not None:
                entries.append(
                    {
                        "at": alert.created_at,
                        "type": "alert",
                        "title": f"Linked alert: {alert.rule_title}",
                        "detail": f"{alert.severity} x{alert.count} (status {alert.status})",
                    }
                )
        entries.sort(key=lambda entry: entry["at"])
        return entries

    # -------------------------------------------------------------- summary
    def summary(self) -> dict:
        rows = self.db.execute(
            select(Case.status, func.count(Case.id)).group_by(Case.status)
        ).all()
        counts = {CaseStatus.OPEN: 0, CaseStatus.IN_PROGRESS: 0, CaseStatus.RESOLVED: 0, CaseStatus.CLOSED: 0}
        counts.update({status: count for status, count in rows})
        return {
            "open_count": counts[CaseStatus.OPEN],
            "in_progress_count": counts[CaseStatus.IN_PROGRESS],
            "resolved_count": counts[CaseStatus.RESOLVED],
            "closed_count": counts[CaseStatus.CLOSED],
            "total_open": counts[CaseStatus.OPEN] + counts[CaseStatus.IN_PROGRESS],
        }


def _load(raw: str | None):
    if not raw:
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return raw
