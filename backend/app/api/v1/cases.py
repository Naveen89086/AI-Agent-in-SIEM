"""Investigation case endpoints (function 7)."""

from fastapi import APIRouter, Query

from app.api.deps import AnalystOrAdmin, CurrentUser, DbSession
from app.api.responses import Page, paginate
from app.models.case import Case
from app.schemas.case import (
    CaseArtifactCreate,
    CaseArtifactRead,
    CaseCreate,
    CaseNoteCreate,
    CaseNoteRead,
    CaseRead,
    CaseUpdate,
)
from app.services.case_service import CaseService

router = APIRouter()


@router.get("", response_model=Page[CaseRead])
def list_cases(
    user: AnalystOrAdmin,
    db: DbSession,
    status: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    assignee: str | None = Query(default=None),
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=500),
) -> dict:
    rows, total = CaseService(db).list_cases(
        status=status, severity=severity, assignee=assignee, offset=offset, limit=limit
    )
    return paginate(rows, total, offset, limit)


@router.get("/summary", response_model=dict)
def case_summary(user: AnalystOrAdmin, db: DbSession) -> dict:
    return CaseService(db).summary()


@router.post("", response_model=CaseRead, status_code=201)
def create_case(
    payload: CaseCreate,
    user: CurrentUser,
    db: DbSession,
) -> Case:
    return CaseService(db).create(payload, author=user.username)


@router.get("/{case_id}", response_model=CaseRead)
def get_case(case_id: str, user: AnalystOrAdmin, db: DbSession) -> Case:
    return CaseService(db).get(case_id)


@router.patch("/{case_id}", response_model=CaseRead)
def update_case(
    case_id: str,
    payload: CaseUpdate,
    user: CurrentUser,
    db: DbSession,
) -> Case:
    return CaseService(db).update(case_id, payload, author=user.username)


@router.delete("/{case_id}", status_code=204)
def delete_case(case_id: str, user: AnalystOrAdmin, db: DbSession) -> None:
    CaseService(db).delete(case_id)


# -------------------------------------------------------------------- notes
@router.get("/{case_id}/notes", response_model=list[CaseNoteRead])
def list_notes(case_id: str, user: AnalystOrAdmin, db: DbSession) -> list:
    return CaseService(db).list_notes(case_id)


@router.post("/{case_id}/notes", response_model=CaseNoteRead, status_code=201)
def add_note(
    case_id: str,
    payload: CaseNoteCreate,
    user: CurrentUser,
    db: DbSession,
) -> object:
    return CaseService(db).add_note(case_id, payload, author=user.username)


# ---------------------------------------------------------------- artifacts
@router.get("/{case_id}/artifacts", response_model=list[CaseArtifactRead])
def list_artifacts(case_id: str, user: AnalystOrAdmin, db: DbSession) -> list:
    return CaseService(db).list_artifacts(case_id)


@router.post("/{case_id}/artifacts", response_model=CaseArtifactRead, status_code=201)
def add_artifact(
    case_id: str,
    payload: CaseArtifactCreate,
    user: AnalystOrAdmin,
    db: DbSession,
) -> object:
    return CaseService(db).add_artifact(case_id, payload)


# ------------------------------------------------------------------ timeline
@router.get("/{case_id}/timeline", response_model=list[dict])
def case_timeline(case_id: str, user: AnalystOrAdmin, db: DbSession) -> list:
    return CaseService(db).timeline(case_id)
