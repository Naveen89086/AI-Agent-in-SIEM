"""Event bus abstraction.

The bus decouples ingest (producers) from the analysis pipeline (consumers)
and follows the publish/subscribe + consumer-group pattern used by real SIEM
messaging layers.

Topics (Redis Streams):
    raw.events          - raw events after collection (ingest -> pipeline)
    normalized.events   - ECS-aligned events (normalizer -> detectors/store)
    detections          - detection results (detectors -> alerter/AI agent)
    alerts              - final alerts (alerter -> SOAR / notifications)
"""

import asyncio
import json
import uuid
from abc import ABC, abstractmethod
from collections.abc import AsyncIterator
from typing import Any

from app.core.config import settings
from app.core.logging import get_logger

log = get_logger("siem.bus")


class Topics:
    RAW_EVENTS = "raw.events"
    NORMALIZED_EVENTS = "normalized.events"
    DETECTIONS = "detections"
    ALERTS = "alerts"
    IOC_MATCHES = "ioc.matches"
    HUNT_MATCHES = "hunt.matches"
    VULN_SCANS = "vuln.scans"


class EventBus(ABC):
    """Publish/subscribe event bus with at-least-once delivery semantics."""

    @abstractmethod
    async def publish(self, topic: str, event: dict[str, Any]) -> None:
        """Publish a single event dict to a topic."""

    @abstractmethod
    async def publish_many(self, topic: str, events: list[dict[str, Any]]) -> None:
        """Publish a batch of events."""

    @abstractmethod
    async def subscribe(
        self,
        topics: list[str],
        group: str,
        consumer: str,
        *,
        block_ms: int = 500,
    ) -> AsyncIterator[tuple[str, dict[str, Any], str]]:
        """Yield (topic, event, message_id) for a consumer group."""

    @abstractmethod
    async def ack(self, topic: str, group: str, message_id: str) -> None:
        """Acknowledge a consumed message."""

    @abstractmethod
    async def pending_count(self, topic: str, group: str) -> int:
        """Number of unacknowledged messages (lag indicator)."""


class InMemoryBus(EventBus):
    """Thread/asyncio-safe in-memory bus for development and tests."""

    def __init__(self) -> None:
        self._queues: dict[str, asyncio.Queue] = {}
        self._lock = asyncio.Lock()
        self._counter: dict[str, int] = {}
        self._pending: dict[str, set[str]] = {}
        self._seen: set[tuple[str, str, str]] = set()

    def _queue(self, topic: str) -> asyncio.Queue:
        if topic not in self._queues:
            self._queues[topic] = asyncio.Queue()
            self._counter[topic] = 0
            self._pending[topic] = set()
        return self._queues[topic]

    async def publish(self, topic: str, event: dict[str, Any]) -> None:
        await self.publish_many(topic, [event])

    async def publish_many(self, topic: str, events: list[dict[str, Any]]) -> None:
        q = self._queue(topic)
        async with self._lock:
            for event in events:
                msg_id = f"{topic}-{self._counter[topic]}"
                self._counter[topic] += 1
                await q.put((msg_id, event))
                self._pending[topic].add(msg_id)

    async def subscribe(
        self,
        topics: list[str],
        group: str,
        consumer: str,
        *,
        block_ms: int = 500,
    ) -> AsyncIterator[tuple[str, dict[str, Any], str]]:
        queues = [self._queue(t) for t in topics]
        while True:
            delivered = False
            for idx, q in enumerate(queues):
                try:
                    msg_id, event = q.get_nowait()
                except asyncio.QueueEmpty:
                    continue
                delivered = True
                yield topics[idx], event, msg_id
            if not delivered:
                await asyncio.sleep(block_ms / 1000)

    async def ack(self, topic: str, group: str, message_id: str) -> None:
        self._pending.get(topic, set()).discard(message_id)

    async def pending_count(self, topic: str, group: str) -> int:
        return len(self._pending.get(topic, set()))


class RedisStreamBus(EventBus):
    """Redis Streams backed bus with consumer groups (reliable, ordered)."""

    def __init__(self, url: str) -> None:
        import redis.asyncio as aioredis

        self._redis = aioredis.from_url(url, decode_responses=True)

    @staticmethod
    def _encode(event: dict[str, Any]) -> dict[str, str]:
        return {"payload": json.dumps(event, default=str)}

    @staticmethod
    def _decode(payload: str) -> dict[str, Any]:
        return json.loads(payload)

    async def publish(self, topic: str, event: dict[str, Any]) -> None:
        await self._redis.xadd(topic, self._encode(event))

    async def publish_many(self, topic: str, events: list[dict[str, Any]]) -> None:
        if not events:
            return
        pipe = self._redis.pipeline()
        for event in events:
            pipe.xadd(topic, self._encode(event))
        await pipe.execute()

    async def subscribe(
        self,
        topics: list[str],
        group: str,
        consumer: str,
        *,
        block_ms: int = 500,
    ) -> AsyncIterator[tuple[str, dict[str, Any], str]]:
        for topic in topics:
            try:
                await self._redis.xgroup_create(topic, group, id="0", mkstream=True)
            except Exception:  # group already exists
                pass
        while True:
            try:
                streams = await self._redis.xreadgroup(
                    group,
                    consumer,
                    {t: ">" for t in topics},
                    count=10,
                    block=block_ms,
                )
            except Exception as exc:  # pragma: no cover - network resilience
                log.warning("Redis stream read failed: %s", exc)
                await asyncio.sleep(1)
                continue
            for topic, messages in streams:
                for message_id, fields in messages:
                    try:
                        event = self._decode(fields["payload"])
                    except (KeyError, json.JSONDecodeError):
                        await self.ack(topic, group, message_id)
                        continue
                    yield topic, event, message_id

    async def ack(self, topic: str, group: str, message_id: str) -> None:
        await self._redis.xack(topic, group, message_id)

    async def pending_count(self, topic: str, group: str) -> int:
        try:
            info = await self._redis.xpending(topic, group)
            return int(info.get("pending", 0)) if info else 0
        except Exception:
            return 0


def build_event_bus(url: str | None = None) -> EventBus:
    """Factory: choose bus implementation from the configured URL."""
    url = url or settings.event_bus_url
    if url.startswith("redis"):
        return RedisStreamBus(url)
    return InMemoryBus()


def new_event_id() -> str:
    return str(uuid.uuid4())


def stamp(event: dict[str, Any]) -> dict[str, Any]:
    """Attach ingestion metadata to an event."""
    event.setdefault("event_id", new_event_id())
    event.setdefault("@timestamp", None)  # set by normalizer when absent
    return event
