"""Detection orchestration (function 4).

Runs every detection engine over each normalized event and publishes a
single stream of `Detection` objects on the `detections` topic:

  1. correlation (Sigma-style rules, time windows)  - M3
  2. signatures (YAML) + native YARA                 - M4
  3. ML behavioral anomaly (IsolationForest+KMeans)  - M4

Engines that are not configured/available degrade to no-ops so a fresh
deployment runs with zero external setup.
"""

import logging
from pathlib import Path
from typing import Any

from app.core.config import settings
from app.pipeline.anomaly_detector import AnomalyDetector
from app.pipeline.bus import EventBus, Topics
from app.pipeline.correlator import Correlator
from app.pipeline.detection import Detection
from app.pipeline.rules import RuleSet
from app.pipeline.yara_matcher import YaraMatcher, build_signature_matcher

log = logging.getLogger("siem.detection")

RULES_DIR = Path(__file__).resolve().parents[1] / "rules"


class DetectionService:
    def __init__(self, bus: EventBus) -> None:
        self.bus = bus
        self.correlator = Correlator(
            bus,
            RuleSet.load_dir(RULES_DIR),
            auto_publish=False,
        )
        self.signatures = build_signature_matcher()
        self.yara = YaraMatcher()
        self.anomaly = AnomalyDetector(
            settings.ml_model_dir,
            settings.ml_anomaly_threshold,
        )
        log.info(
            "DetectionService ready (rules=%d, signatures=%d, yara=%s, ml=%s)",
            len(self.correlator.rules.active()),
            len(self.signatures.rules),
            self.yara.available,
            self.anomaly.is_fitted,
        )

    async def process_event(self, event: dict[str, Any]) -> list[Detection]:
        detections = await self.correlator.process_event(event)
        detections += self.signatures.match(event)
        detections += self.yara.match(event)
        anomaly = self.anomaly.is_anomalous(event)
        if anomaly is not None:
            detections.append(anomaly)

        for detection in detections:
            await self.bus.publish(Topics.DETECTIONS, detection.to_dict())
        return detections

    async def run(self, group: str = "detectors") -> None:
        """Consume normalized events and run all detectors."""
        import uuid

        consumer = f"detectors-{uuid.uuid4().hex[:6]}"
        log.info("DetectionService consuming %s as %s", Topics.NORMALIZED_EVENTS, consumer)
        async for topic, event, msg_id in self.bus.subscribe(
            [Topics.NORMALIZED_EVENTS], group, consumer
        ):
            try:
                await self.process_event(event)
            except Exception:
                log.exception("Detection failed (event=%s)", event.get("event_id"))
            await self.bus.ack(topic, group, msg_id)
