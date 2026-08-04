"""Machine-learning anomaly detection (function 4, part 2).

Behavioral detection that complements rule-based correlation:

  - EventFeatureExtractor builds a fixed-size numeric vector per normalized
    event (hashed categorical buckets + log-scaled ports).
  - AnomalyDetector trains an IsolationForest + KMeans baseline on historical
    events. Events that deviate strongly (combined score > threshold) are
    flagged as anomalies. A lightweight feedback loop (JSONL) lets analysts
    label events and re-train so the model adapts over time.

Models persist to ML_MODEL_DIR via joblib. Without a fitted model the
detector is a harmless no-op, so a fresh deployment degrades gracefully.
"""

import hashlib
import json
import logging
import time
from pathlib import Path
from typing import Any

import numpy as np
from sklearn.cluster import KMeans
from sklearn.ensemble import IsolationForest

from app.core.config import settings
from app.pipeline.detection import Detection, summarize_event

log = logging.getLogger("siem.detectors.ml")

MODEL_FILENAME = "anomaly_model.joblib"
FEEDBACK_FILENAME = "feedback.jsonl"

CATEGORICAL_FIELDS = [
    "event.action",
    "event.category",
    "source.ip",
    "destination.ip",
    "user.name",
    "process.name",
    "host.name",
    "url.path",
]
NUM_CAT_FIELDS = len(CATEGORICAL_FIELDS)
BUCKETS_PER_FIELD = 64
NUMERIC_DIM = 2  # source.port, destination.port (log-scaled)


class EventFeatureExtractor:
    """Deterministic, persistent-safe event -> feature vector conversion."""

    def __init__(self) -> None:
        self._dim = NUM_CAT_FIELDS * BUCKETS_PER_FIELD + NUMERIC_DIM

    @property
    def dim(self) -> int:
        return self._dim

    @staticmethod
    def _dig(event: dict[str, Any], dotted: str) -> Any:
        node: Any = event
        for part in dotted.split("."):
            if isinstance(node, dict) and part in node:
                node = node[part]
            else:
                return None
        return node

    @staticmethod
    def _bucket(text: str, salt: int) -> int:
        digest = hashlib.md5(f"{salt}:{text}".encode("utf-8")).hexdigest()
        return int(digest[:8], 16) % BUCKETS_PER_FIELD

    def transform(self, events: list[dict[str, Any]]) -> np.ndarray:
        rows = []
        for event in events:
            row = np.zeros(self._dim, dtype=np.float32)
            for i, field in enumerate(CATEGORICAL_FIELDS):
                value = self._dig(event, field)
                if isinstance(value, list):
                    text = "|".join(str(v) for v in value)
                elif value is None:
                    text = "<none>"
                else:
                    text = str(value)
                offset = i * BUCKETS_PER_FIELD
                row[offset + self._bucket(text, i)] = 1.0
            sport = self._dig(event, "source.port")
            dport = self._dig(event, "destination.port")
            row[NUM_CAT_FIELDS * BUCKETS_PER_FIELD] = float(np.log1p(sport or 0))
            row[NUM_CAT_FIELDS * BUCKETS_PER_FIELD + 1] = float(np.log1p(dport or 0))
            rows.append(row)
        return np.vstack(rows) if rows else np.zeros((0, self._dim), dtype=np.float32)


class AnomalyDetector:
    """IsolationForest + KMeans anomaly scorer with feedback refinement."""

    def __init__(
        self,
        model_dir: str | Path | None = None,
        threshold: float | None = None,
    ) -> None:
        self.model_dir = Path(model_dir or settings.ml_model_dir)
        self.threshold = (
            threshold if threshold is not None else settings.ml_anomaly_threshold
        )
        self.extractor = EventFeatureExtractor()
        self._model_path = self.model_dir / MODEL_FILENAME
        self._feedback_path = self.model_dir / FEEDBACK_FILENAME
        self._model: dict[str, Any] | None = None
        self._load()

    # ------------------------------------------------------------------ model
    def _load(self) -> None:
        try:
            import joblib

            if self._model_path.exists():
                self._model = joblib.load(self._model_path)
                log.info("Loaded ML anomaly model from %s", self._model_path)
        except Exception as exc:
            log.warning("Could not load ML anomaly model: %s", exc)
            self._model = None

    @property
    def is_fitted(self) -> bool:
        return self._model is not None

    def fit(self, events: list[dict[str, Any]], min_samples: int = 20) -> bool:
        if len(events) < min_samples:
            log.info("Not enough events to train (%d < %d)", len(events), min_samples)
            self._model = None
            return False
        X = self.extractor.transform(events)
        iso = IsolationForest(n_estimators=100, contamination="auto", random_state=42)
        iso.fit(X)
        if_scores = iso.score_samples(X)

        n_clusters = max(2, min(8, len(set(_row_bucket(X)))))
        km = KMeans(n_clusters=n_clusters, n_init=10, random_state=42)
        km.fit(X)
        distances = km.transform(X).min(axis=1)

        self._model = {
            "iso": iso,
            "km": km,
            "if_low": float(np.percentile(if_scores, 5)),
            "if_high": float(np.percentile(if_scores, 95)),
            "dist_p95": float(np.percentile(distances, 95)) or 1.0,
            "n_train": int(len(events)),
            "trained_at": time.time(),
        }
        self._save()
        log.info("Trained anomaly model on %d events", len(events))
        return True

    def _save(self) -> None:
        self.model_dir.mkdir(parents=True, exist_ok=True)
        try:
            import joblib

            joblib.dump(self._model, self._model_path)
        except Exception as exc:  # pragma: no cover - filesystem edge cases
            log.warning("Could not persist ML model: %s", exc)

    # ---------------------------------------------------------------- scoring
    def score(self, event: dict[str, Any]) -> dict[str, float] | None:
        """Return anomaly score breakdown, or None if no model is fitted."""
        if not self._model:
            return None
        x = self.extractor.transform([event])[0]
        iso = self._model["iso"]
        km = self._model["km"]
        if_low = self._model["if_low"]
        if_high = self._model["if_high"]
        dist_p95 = self._model["dist_p95"]

        if_score = float(iso.score_samples([x])[0])
        # normalize against the training score distribution (percentile band)
        if_range = if_high - if_low or 1.0
        if_norm = float(np.clip((if_high - if_score) / if_range, 0.0, 1.0))

        distance = float(km.transform([x]).min())
        dist_norm = float(np.clip(distance / (dist_p95 * 2), 0.0, 1.0))

        total = 0.7 * if_norm + 0.3 * dist_norm
        return {
            "score": round(total, 4),
            "isolation_forest": round(if_norm, 4),
            "cluster_distance": round(dist_norm, 4),
        }

    def is_anomalous(self, event: dict[str, Any]) -> Detection | None:
        breakdown = self.score(event)
        if breakdown is None or breakdown["score"] < self.threshold:
            return None
        return Detection(
            rule_id="ml-anomaly",
            rule_title="Behavioral Anomaly Detected",
            severity="medium",
            description=(
                "Machine-learning model flagged this event as an outlier versus "
                "the established event baseline."
            ),
            detector="ml",
            event_ids=[event.get("event_id", "")],
            events=[summarize_event(event)],
            tags=["ml", "anomaly"],
            score=breakdown["score"],
            metadata={"scores": breakdown},
        )

    # --------------------------------------------------------------- feedback
    def add_feedback(self, event: dict[str, Any], is_anomaly: bool) -> None:
        """Label an event (positive = genuinely anomalous) for future re-training."""
        self.model_dir.mkdir(parents=True, exist_ok=True)
        record = {
            "event_id": event.get("event_id"),
            "label": 1 if is_anomaly else 0,
            "features": self.extractor.transform([event])[0].tolist(),
            "ts": time.time(),
        }
        with self._feedback_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record) + "\n")
        log.info("Recorded feedback for event %s", record["event_id"])

    def retrain(self, base_events: list[dict[str, Any]]) -> bool:
        """Re-train on base events plus analyst feedback (positive labels
        sampled more heavily so they shift the baseline)."""
        X = self.extractor.transform(base_events)
        labels = np.zeros(len(base_events), dtype=int)
        positive: list[np.ndarray] = []
        if self._feedback_path.exists():
            for line in self._feedback_path.read_text(encoding="utf-8").splitlines():
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if rec.get("label"):
                    positive.append(np.asarray(rec["features"], dtype=np.float32))
        if len(base_events) < 20 and len(positive) < 20:
            log.info("Not enough training material to retrain")
            return False
        if positive:
            X = np.vstack([X, np.asarray(positive)])
            labels = np.hstack([labels, np.ones(len(positive), dtype=int)])

        iso = IsolationForest(n_estimators=100, contamination="auto", random_state=42)
        iso.fit(X)
        if_scores = iso.score_samples(X)
        km = KMeans(n_clusters=max(2, min(8, len(set(_row_bucket(X))))), n_init=10, random_state=42)
        km.fit(X)
        distances = km.transform(X).min(axis=1)
        self._model = {
            "iso": iso,
            "km": km,
            "if_low": float(np.percentile(if_scores, 5)),
            "if_high": float(np.percentile(if_scores, 95)),
            "dist_p95": float(np.percentile(distances, 95)) or 1.0,
            "n_train": int(len(X)),
            "trained_at": time.time(),
        }
        self._save()
        log.info("Retrained anomaly model on %d samples (incl. %d feedback)",
                 len(X), len(positive))
        return True


def _row_bucket(X: np.ndarray) -> list[str]:
    """Stable per-row identity used to pick a KMeans cluster count."""
    return ["|".join(str(int(v)) for v in row) for row in X]
