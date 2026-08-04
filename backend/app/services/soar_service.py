"""SOAR execution service (function 10).

Evaluates playbooks against an alert context, executes actions through
pluggable connectors (with destructive actions gated by configuration),
and persists an audit trail of every step.
"""

import logging
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.exceptions import ValidationError
from app.models.action import SoarAction
from app.pipeline.playbooks import (
    Playbook,
    PlaybookSet,
    render_template,
    resolve_env,
)

log = logging.getLogger("siem.soar")


def _extract_value(context: dict[str, Any], path: str) -> Any:
    if path in context:
        return context[path]
    node: Any = context
    for part in path.split("."):
        if isinstance(node, dict) and part in node:
            node = node[part]
        else:
            return None
    return node


class Connectors:
    """HTTP / email connectors. Destructive actions require opt-in."""

    def __init__(self, http_client=None, notifier=None) -> None:
        self._http = http_client
        self._notifier = notifier

    async def _post(self, url: str, payload: dict) -> str:
        if self._http is None:
            import httpx

            self._http = httpx.AsyncClient(timeout=10.0)
        response = await self._http.post(url, json=payload)
        response.raise_for_status()
        return f"HTTP {response.status_code}"

    async def run(self, action: dict, context: dict[str, Any]) -> str:
        action_type = action["type"]
        url = render_template(action.get("url", ""), context) or None
        if url:
            url = resolve_env(url) or None
        payload_template = action.get("payload")
        payload: dict[str, Any] = {}
        if isinstance(payload_template, dict):
            for key, value in payload_template.items():
                payload[key] = render_template(str(value), context)

        if action_type in ("block_ip", "isolate_host", "kill_process"):
            if not settings.soar_allow_destructive:
                raise PermissionError("destructive SOAR actions are disabled (SOAR_ALLOW_DESTRUCTIVE)")
            target_field = action.get("target", "source.ip")
            target = _extract_value(context, target_field)
            if target is None:
                raise ValueError(f"target field '{target_field}' not found in alert context")
            api = action.get("api") or {
                "block_ip": settings.soar_firewall_block_api,
                "isolate_host": settings.soar_endpoint_isolation_api,
                "kill_process": settings.soar_endpoint_isolation_api,
            }.get(action_type)
            if api:
                api = resolve_env(api) or None
            if not api:
                raise ValueError(f"no endpoint configured for {action_type}")
            body = dict(payload)
            body.setdefault("action", action_type)
            body.setdefault("target", target)
            detail = await self._post(api, body)
            return f"{action_type} -> {target} ({detail})"

        if action_type == "webhook":
            if not url:
                url = settings.soar_webhook_default_url
            if not url:
                raise ValueError("webhook action has no url")
            detail = await self._post(url, payload)
            return f"webhook {url} ({detail})"

        if action_type == "email":
            if self._notifier is None:
                from app.services.notifications import send_email

                if not (settings.smtp_host and settings.smtp_user):
                    raise ValueError("email action requires SMTP configuration")
                self._notifier = lambda to, subject, body: send_email(to, subject, body)
            to = render_template(action.get("to", ""), context)
            subject = render_template(action.get("subject", f"[SIEM] {action_type}"), context)
            body = render_template(action.get("body", ""), context)
            await self._notifier(to=to, subject=subject, body=body)
            return f"email -> {to}"

        raise ValidationError(f"unsupported action type: {action_type}")


class SoarService:
    def __init__(self, db: Session, playbook_set: PlaybookSet | None = None, connectors: Connectors | None = None) -> None:
        self.db = db
        self.playbooks = playbook_set or PlaybookSet.load_dir(settings.soar_playbooks_dir)
        self.connectors = connectors or Connectors()

    # ------------------------------------------------------------ evaluation
    async def execute_for_alert(self, alert: dict[str, Any]) -> list[SoarAction]:
        records: list[SoarAction] = []
        for playbook in self.playbooks.match(alert):
            records.extend(await self.execute(playbook.id, alert))
        return records

    async def execute(self, playbook_id: str, alert: dict[str, Any]) -> list[SoarAction]:
        playbook = self.playbooks.get(playbook_id)
        if playbook is None:
            raise ValidationError(f"playbook '{playbook_id}' not found")
        context = self._context(alert)
        records: list[SoarAction] = []
        for step in playbook.actions:
            action_type = step["type"]
            record = SoarAction(
                playbook_id=playbook.id,
                playbook_name=playbook.name,
                alert_id=str(alert.get("id") or ""),
                rule_id=str(alert.get("rule_id") or ""),
                action_type=action_type,
                status="pending",
                target=str(_extract_value(context, step.get("target", "source.ip")) or ""),
            )
            try:
                detail = await self.connectors.run(step, context)
                record.status = "success"
                record.detail = detail
            except PermissionError as exc:
                record.status = "skipped"
                record.detail = str(exc)
            except Exception as exc:
                record.status = "failed"
                record.detail = str(exc)
            self.db.add(record)
            records.append(record)
        self.db.commit()
        return records

    @staticmethod
    def _context(alert: dict[str, Any]) -> dict[str, Any]:
        context: dict[str, Any] = {}
        for key, value in (alert or {}).items():
            if isinstance(value, (dict, list)):
                context[key] = value
            else:
                context[key] = value
        grouping = (alert or {}).get("grouping")
        if isinstance(grouping, dict):
            for key, value in grouping.items():
                if key not in context:
                    context[key] = value
        return context

    # ------------------------------------------------------------- audit trail
    def list_actions(
        self, *, playbook_id: str | None = None, alert_id: str | None = None, status: str | None = None, limit: int = 50
    ) -> tuple[list[SoarAction], int]:
        query = select(SoarAction)
        count_query = select(func.count(SoarAction.id))
        if playbook_id:
            query = query.where(SoarAction.playbook_id == playbook_id)
            count_query = count_query.where(SoarAction.playbook_id == playbook_id)
        if alert_id:
            query = query.where(SoarAction.alert_id == alert_id)
            count_query = count_query.where(SoarAction.alert_id == alert_id)
        if status:
            query = query.where(SoarAction.status == status)
            count_query = count_query.where(SoarAction.status == status)
        total = self.db.scalar(count_query) or 0
        rows = list(self.db.scalars(query.order_by(SoarAction.created_at.desc()).limit(limit)).all())
        return rows, total
