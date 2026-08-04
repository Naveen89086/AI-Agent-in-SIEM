"""Module 4 - threat detection tests (signatures, YARA, ML anomaly)."""

import tempfile
from pathlib import Path

from app.pipeline.anomaly_detector import AnomalyDetector, EventFeatureExtractor
from app.pipeline.detection import Detection
from app.pipeline.yara_matcher import SignatureMatcher, SignatureRule, YaraMatcher

BUNDLED_SIGNATURES = Path(__file__).resolve().parents[2] / "data" / "yara" / "signatures"


def _event(**overrides) -> dict:
    ev = {
        "event_id": "evt-1",
        "@timestamp": "2026-08-01T12:00:01+00:00",
        "event": {"action": "process_created", "category": ["process"]},
        "source": {"ip": "10.0.0.5", "port": 50000},
        "destination": {"ip": "10.0.0.9", "port": 443},
        "host": {"name": "workstation-01"},
        "process": {"name": "powershell.exe", "command_line": "powershell.exe -EncodedCommand AA=="},
        "user": {"name": "alice"},
        "message": "powershell launched",
    }
    ev.update(overrides)
    return ev


def _sig(**overrides) -> SignatureRule:
    base = {
        "title": "Suspicious Process",
        "id": "sig-1",
        "description": "test signature",
        "severity": "high",
        "match": {"process.name": "mimikatz.exe"},
    }
    base.update(overrides)
    return SignatureRule.from_mapping(base, "test.yml")


# ------------------------------------------------------------------ signatures
def test_signature_exact_match():
    matcher = SignatureMatcher([_sig()])
    detections = matcher.match(
        _event(process={"name": "mimikatz.exe", "command_line": "mimikatz.exe"})
    )
    assert len(detections) == 1
    assert detections[0].detector == "signature"
    assert detections[0].rule_title == "Suspicious Process"
    assert detections[0].severity == "high"


def test_signature_contains_match():
    matcher = SignatureMatcher(
        [_sig(match={"process.command_line contains": "privilege::debug"})]
    )
    hit = matcher.match(
        _event(process={"name": "mimikatz.exe", "command_line": "mimikatz.exe privilege::debug sekurlsa"})
    )
    assert len(hit) == 1
    assert matcher.match(_event(process={"name": "mimikatz.exe", "command_line": "mimikatz.exe /? "})) == []


def test_signature_list_value_match():
    matcher = SignatureMatcher(
        [
            _sig(
                match={
                    "file.hash.md5": [
                        "e8d8b8b8b8b8b8b8b8b8b8b8b8b8b8b8",
                        "5bd1234a8f4f2f2f2f2f2f2f2f2f2f2f",
                    ]
                }
            )
        ]
    )
    hit = matcher.match(_event(file={"hash": {"md5": "5bd1234a8f4f2f2f2f2f2f2f2f2f2f2f"}}))
    assert len(hit) == 1


def test_signature_no_false_positive():
    matcher = SignatureMatcher([_sig()])
    assert matcher.match(_event()) == []


def test_signature_load_bundled_rules():
    matcher = SignatureMatcher.load_dir(BUNDLED_SIGNATURES)
    assert len(matcher.rules) >= 4
    assert matcher.match(
        _event(process={"name": "powershell.exe", "command_line": "powershell.exe -EncodedCommand Zg=="})
    )


def test_signature_case_insensitive():
    matcher = SignatureMatcher([_sig(match={"user.name": "Admin"})])
    assert matcher.match(_event(user={"name": "admin"}))
    assert matcher.match(_event(user={"name": "ADMIN"}))


# ----------------------------------------------------------------------- yara
def test_yara_matcher_degrades_when_unavailable():
    matcher = YaraMatcher(rules_dir=tempfile.mkdtemp())
    if matcher.available:  # pragma: no cover - only when native lib present
        return
    assert matcher.match(_event()) == []


# ------------------------------------------------------------- feature extractor
def test_feature_extractor_deterministic():
    ext = EventFeatureExtractor()
    a = ext.transform([_event(), _event()])
    assert a.shape == (2, ext.dim)
    assert (a[0] == a[1]).all()


# ----------------------------------------------------------------------- ml
def test_anomaly_not_fitted_is_noop():
    det = AnomalyDetector(model_dir=tempfile.mkdtemp())
    assert det.is_fitted is False
    assert det.score(_event()) is None
    assert det.is_anomalous(_event()) is None


def _normal_events(n: int = 60) -> list[dict]:
    # near-identical "monitoring baseline" events: tight cluster, low entropy
    return [
        _event(
            event_id=f"n{i}",
            event={"action": "ssh_failed_login", "category": ["authentication"]},
            source={"ip": "10.10.0.5", "port": 30000 + (i % 20)},
            destination={"ip": "10.0.0.1", "port": 22},
            user={"name": "alice"},
            process={"name": "sshd", "command_line": "/usr/sbin/sshd"},
        )
        for i in range(n)
    ]


def _outlier_event() -> dict:
    return _event(
        event_id="outlier-1",
        event={"action": "anomalous_crypto_tool", "category": ["process"]},
        source={"ip": "192.0.2.99", "port": 65535},
        destination={"ip": "203.0.113.1", "port": 65534},
        process={"name": "mysterytool.exe", "command_line": "mysterytool.exe --dump"},
        user={"name": "nobody"},
    )


def test_anomaly_training_and_persistence():
    tmp = tempfile.mkdtemp()
    det = AnomalyDetector(model_dir=tmp)
    assert det.fit(_normal_events()) is True
    assert det.is_fitted is True
    assert (Path(tmp) / "anomaly_model.joblib").exists()

    # reload from disk
    reloaded = AnomalyDetector(model_dir=tmp)
    assert reloaded.is_fitted is True


def test_anomaly_outlier_flagged_normal_not():
    tmp = tempfile.mkdtemp()
    det = AnomalyDetector(model_dir=tmp, threshold=0.1)
    normals = _normal_events()
    det.fit(normals)

    normal_scores = [det.score(e)["score"] for e in normals]
    max_normal = max(normal_scores)
    outlier_score = det.score(_outlier_event())
    assert outlier_score is not None
    assert outlier_score["score"] > max_normal
    assert outlier_score["cluster_distance"] > 0.5  # far from baseline clusters

    # with a threshold just above the normal band, only the outlier fires
    det2 = AnomalyDetector(model_dir=tmp, threshold=min(max_normal + 0.02, 0.95))
    assert det2.is_anomalous(normals[0]) is None

    hit = det2.is_anomalous(_outlier_event())
    assert hit is not None
    assert isinstance(hit, Detection)
    assert hit.detector == "ml"
    assert hit.rule_id == "ml-anomaly"
    assert hit.score == outlier_score["score"]
    assert hit.metadata["scores"]["isolation_forest"] == outlier_score["isolation_forest"]


def test_anomaly_insufficient_data_skips_training():
    det = AnomalyDetector(model_dir=tempfile.mkdtemp())
    assert det.fit(_normal_events(3)) is False
    assert det.is_fitted is False


def test_anomaly_feedback_and_retrain():
    tmp = tempfile.mkdtemp()
    det = AnomalyDetector(model_dir=tmp, threshold=0.1)
    det.fit(_normal_events())

    det.add_feedback(_outlier_event(), is_anomaly=True)
    det.add_feedback(_normal_events()[0], is_anomaly=False)
    feedback_file = Path(tmp) / "feedback.jsonl"
    assert feedback_file.exists()

    assert det.retrain(_normal_events()) is True
    assert det.is_fitted is True
    # feedback-influenced model still flags the outlier
    assert det.is_anomalous(_outlier_event()) is not None
