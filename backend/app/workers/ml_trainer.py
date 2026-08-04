"""ML model training worker (off-line).

Builds the behavioral anomaly baseline from events already stored in the log
store, then persists the fitted model for the pipeline's AnomalyDetector.

Usage:
    python -m app.workers.ml_trainer --samples 5000
"""

import argparse
import asyncio
import logging

from app.core.logging import setup_logging
from app.pipeline.anomaly_detector import AnomalyDetector
from app.storage.base import SearchQuery, build_log_store

setup_logging()
log = logging.getLogger("siem.worker.ml_trainer")


async def train(samples: int = 5000) -> None:
    store = build_log_store()
    query = SearchQuery(text=None, size=samples, sort_order="asc")
    response = await store.search(query)
    events = [hit.source for hit in response.hits]
    log.info("Loaded %d historical events for training", len(events))

    detector = AnomalyDetector()
    if not detector.fit(events):
        log.warning("Training skipped - need at least 20 events. Ingest some first.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Train the ML anomaly baseline")
    parser.add_argument("--samples", type=int, default=5000)
    args = parser.parse_args()
    asyncio.run(train(args.samples))


if __name__ == "__main__":
    main()
