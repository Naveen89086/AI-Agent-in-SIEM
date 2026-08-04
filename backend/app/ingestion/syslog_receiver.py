"""Syslog receiver (RFC 3164 / RFC 5424) over UDP and TCP.

Listens for syslog datagrams/streams and publishes each message to the
`raw.events` bus topic, tagged with a sensible default source. A full
grammar parser is intentionally out of scope - the normalizer (M2) handles
field extraction with Grok patterns.
"""

import asyncio
import logging
import re
from datetime import datetime, timezone

from app.pipeline.bus import EventBus, Topics, stamp

log = logging.getLogger("siem.ingest.syslog")

_RFC3164_RE = re.compile(
    r"^<(?P<priority>\d{1,3})>(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}) "
    r"(?P<hostname>[\w.\-]+) (?P<message>.*)$"
)
_RFC5424_RE = re.compile(
    r"^<(?P<priority>\d{1,3})>(?P<version>\d) "
    r"(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?) "
    r"(?P<hostname>\S+) (?P<appname>\S+) (?P<procid>\S+) (?P<msgid>\S+) "
    r"(?P<structured>-|\[[^\]]*\]) (?P<message>.*)$"
)

_MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}


def parse_priority(priority: int) -> tuple[int, int]:
    """Split syslog priority into facility and severity (RFC 3164)."""
    return priority // 8, priority % 8


SEVERITY_NAMES = [
    "emergency", "alert", "critical", "error", "warning", "notice", "informational", "debug",
]


class SyslogReceiver:
    """Async UDP + TCP syslog collector."""

    def __init__(
        self,
        bus: EventBus,
        *,
        bind_host: str = "0.0.0.0",
        udp_port: int = 5514,
        tcp_port: int = 5515,
        default_source: str = "syslog",
        max_packet: int = 65535,
    ) -> None:
        self.bus = bus
        self.bind_host = bind_host
        self.udp_port = udp_port
        self.tcp_port = tcp_port
        self.default_source = default_source
        self.max_packet = max_packet

    @staticmethod
    def _parse_message(payload: bytes) -> dict | None:
        line = payload.decode("utf-8", errors="replace").rstrip("\n\r\x00")
        if not line:
            return None
        event: dict = {"raw": line, "tags": ["syslog"]}

        match = _RFC3164_RE.match(line) or _RFC5424_RE.match(line)
        if match:
            pri = int(match.group("priority"))
            facility, severity = parse_priority(pri)
            event["extra"] = {
                "priority": pri,
                "facility": facility,
                "severity": severity,
                "severity_name": SEVERITY_NAMES[severity],
                "syslog_header": match.group(0).split(" ", 1)[0],
            }
            event["host"] = match.group("hostname")
            event["message"] = match.group("message")
            if match.re is _RFC5424_RE:
                event["extra"]["version"] = match.group("version")
            # A raw message even without a matched header is still collected
        else:
            event["message"] = line
        return event

    async def _handle_udp(self) -> None:
        transport, _ = await asyncio.get_event_loop().create_datagram_endpoint(
            lambda: _UdpHandler(self), local_addr=(self.bind_host, self.udp_port)
        )
        log.info("Syslog UDP receiver listening on %s:%s", self.bind_host, self.udp_port)
        await asyncio.Event().wait()  # pragma: no cover - run forever

    async def _handle_tcp(self) -> None:
        async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            peer = writer.get_extra_info("peername")
            try:
                while True:
                    data = await reader.readline()
                    if not data:
                        break
                    await self._publish(data)
            except (ConnectionError, asyncio.CancelledError):
                pass
            finally:
                writer.close()
                await writer.wait_closed()

        server = await asyncio.start_server(handle, self.bind_host, self.tcp_port)
        log.info("Syslog TCP receiver listening on %s:%s", self.bind_host, self.tcp_port)
        async with server:
            await server.serve_forever()

    async def _publish(self, payload: bytes) -> None:
        parsed = self._parse_message(payload)
        if parsed is None:
            return
        raw = stamp(
            {
                "raw": parsed["raw"],
                "source_type": "syslog",
                "source_name": self.default_source,
                "host": parsed.get("host"),
                "message": parsed.get("message", parsed["raw"]),
                "extra": parsed.get("extra", {}),
                "tags": parsed.get("tags", []),
                "received_at": datetime.now(timezone.utc).isoformat(),
                "pipeline": {"ingested": True, "normalized": False},
            }
        )
        await self.bus.publish(Topics.RAW_EVENTS, raw)

    async def run(self) -> None:
        tasks = [
            asyncio.create_task(self._handle_udp()),
            asyncio.create_task(self._handle_tcp()),
        ]
        await asyncio.gather(*tasks)


class _UdpHandler:
    """Datagram protocol handler feeding messages to the receiver."""

    def __init__(self, receiver: SyslogReceiver) -> None:
        self.receiver = receiver

    def datagram_received(self, data: bytes, addr) -> None:
        try:
            asyncio.create_task(self.receiver._publish(data))
        except Exception:
            log.exception("Failed to process syslog datagram from %s", addr)

    def error_received(self, exc) -> None:  # pragma: no cover
        log.warning("Syslog UDP error: %s", exc)
