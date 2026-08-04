"""Notification channels (function 5 - real-time alerting).

AlertService calls these when a NEW alert is created or a known alert crosses
a severity escalation. Channels are guarded by configuration so a fresh
deployment with no webhook/SMTP settings silently no-ops.
"""

import logging
from abc import ABC, abstractmethod
from typing import Any

import httpx

from app.core.config import settings

log = logging.getLogger("siem.notifications")

SEVERITY_RANK = {
    "informational": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


class Notifier(ABC):
    @abstractmethod
    async def notify(self, alert: dict[str, Any], *, is_new: bool) -> None:
        """Deliver an alert payload to the channel."""

    @property
    @abstractmethod
    def enabled(self) -> bool:
        """Whether the channel is configured and usable."""


class WebhookNotifier(Notifier):
    """POST a compact alert payload to a configured webhook URL."""

    def __init__(self, url: str | None = None) -> None:
        self._url = url or settings.alert_webhook_default_url

    @property
    def enabled(self) -> bool:
        return bool(self._url)

    async def notify(self, alert: dict[str, Any], *, is_new: bool) -> None:
        if not self.enabled:
            return
        payload = {
            "event": "alert.new" if is_new else "alert.escalated",
            "alert_id": alert["id"],
            "title": alert["rule_title"],
            "severity": alert["severity"],
            "status": alert["status"],
            "count": alert["count"],
            "rule_id": alert["rule_id"],
            "detector": alert["detector"],
            "description": alert.get("description"),
            "first_seen_at": alert["first_seen_at"].isoformat(),
            "last_seen_at": alert["last_seen_at"].isoformat(),
        }
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                response = await client.post(self._url, json=payload)
                response.raise_for_status()
            log.info("Webhook notification delivered for alert %s", alert["id"])
        except Exception as exc:
            log.warning("Webhook notification failed for alert %s: %s", alert["id"], exc)


def send_email(to: str, subject: str, body: str) -> None:
    """Send a plain-text email via SMTP; raises on any failure."""
    import smtplib
    from email.mime.text import MIMEText

    message = MIMEText(body, "plain", "utf-8")
    message["Subject"] = subject
    message["From"] = settings.smtp_from
    message["To"] = to
    with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=10) as server:
        if settings.smtp_user and settings.smtp_password:
            server.starttls()
            server.login(settings.smtp_user, settings.smtp_password)
        server.send_message(message)


class EmailNotifier(Notifier):
    """SMTP email notification (guarded by smtp_host configuration)."""

    @property
    def enabled(self) -> bool:
        return bool(settings.smtp_host and settings.smtp_user)

    async def notify(self, alert: dict[str, Any], *, is_new: bool) -> None:
        if not self.enabled:
            return
        subject = f"[SIEM {alert['severity'].upper()}] {alert['rule_title']}"
        body = (
            f"Rule: {alert['rule_title']}\n"
            f"Severity: {alert['severity']}\n"
            f"Detector: {alert['detector']}\n"
            f"Occurrences: {alert['count']}\n"
            f"Description: {alert.get('description', '')}\n"
        )
        try:
            send_email(to=settings.smtp_user, subject=subject, body=body)
            log.info("Email notification sent for alert %s", alert["id"])
        except Exception as exc:
            log.warning("Email notification failed for alert %s: %s", alert["id"], exc)


def build_notifiers() -> list[Notifier]:
    """Construct configured channels (no-op when unconfigured)."""
    return [WebhookNotifier(), EmailNotifier()]
