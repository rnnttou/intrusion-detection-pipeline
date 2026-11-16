import json
from pathlib import Path

import numpy as np
import pandas as pd
import pytest
from fastapi.testclient import TestClient

from src.api import app
from src.evaluate import threshold_for_fpr
from src.features import CLASSES, FAMILIES, FEATURES, PORT, build_features
from src.mitre import MITRE, technique
from src.prepare import chrono_split, clean_label
from src.scoring import UNKNOWN, IntrusionScorer

# Six flux réels du jeu de test, un par famille, que le modèle classe sans hésiter
SAMPLES = {s["family"]: s for s in json.loads(Path("tests/sample_flows.json").read_text())}


@pytest.fixture(scope="module")
def scorer():
    return IntrusionScorer()


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:  # le "with" déclenche le lifespan
        yield c


# --- features et préparation ---

def test_features_exclude_port_and_duplicate_column():
    assert len(FEATURES) == 76 and len(set(FEATURES)) == 76
    assert PORT not in FEATURES and "Fwd Header Length.1" not in FEATURES


def test_build_features_keeps_order_and_removes_infinities():
    flow = {**SAMPLES["Benign"]["features"], "Flow Bytes/s": float("inf"), "Flow Packets/s": float("nan")}
    X = build_features(pd.DataFrame([flow]))
    assert X.shape == (1, 76) and X.dtype == np.float32 and np.isfinite(X).all()
    assert X[0, FEATURES.index("Flow Bytes/s")] == 0
    assert X[0, 0] == np.float32(flow["Flow Duration"])


def test_labels_with_broken_dash_map_to_a_family():
    assert clean_label("Web Attack \x96 XSS") == "Web Attack XSS"
    assert FAMILIES[clean_label("Web Attack � Sql Injection")] == "WebAttack"
    assert FAMILIES[clean_label("FTP-Patator")] == "BruteForce"


def test_chrono_split_is_ordered_60_20_20():
    split = chrono_split(100)
    assert list(split[:60]) == ["train"] * 60 and list(split[60:80]) == ["val"] * 20 and list(split[80:]) == ["test"] * 20


def test_threshold_for_fpr_lets_through_the_requested_share():
    scores = np.linspace(0, 1, 10_001)
    assert np.isclose((scores > threshold_for_fpr(scores, 0.01)).mean(), 0.01, atol=1e-3)


# --- MITRE ATT&CK ---

def test_every_attack_class_has_a_technique():
    assert set(MITRE) == set(CLASSES) - {"Benign"}
    assert all(t["id"].startswith("T") and t["name"] and t["tactic"] for t in MITRE.values())
    assert technique("Benign") is None and technique(UNKNOWN) is None


# --- scoring ---

def test_benign_flow_raises_no_alert(scorer):
    r = scorer.score(SAMPLES["Benign"]["features"])
    assert not r["is_alert"] and r["predicted_class"] == "Benign" and r["mitre"] is None and r["detector"] is None


@pytest.mark.parametrize("family", ["DoS", "DDoS", "PortScan", "BruteForce", "WebAttack"])
def test_known_attack_is_classified_and_mapped(scorer, family):
    r = scorer.score(SAMPLES[family]["features"])
    assert r["is_alert"] and r["detector"] == "xgboost" and r["severity"] == "haute"
    assert r["predicted_class"] == family and r["mitre"] == MITRE[family]


def test_anomaly_detector_flags_what_xgboost_calls_benign(scorer):
    # on force XGBoost à se taire : seul l'Isolation Forest peut alors lever l'alerte
    quiet = IntrusionScorer()
    quiet.thr_attack, quiet.thr_anomaly = 2.0, -1.0
    r = quiet.score(SAMPLES["DDoS"]["features"])
    assert r["is_alert"] and r["detector"] == "iforest" and r["predicted_class"] == UNKNOWN
    assert r["severity"] == "basse" and r["mitre"] is None


def test_batch_scoring_matches_single_scoring(scorer):
    flows = [s["features"] for s in SAMPLES.values()]
    for flow, batch in zip(flows, scorer.score_many(flows)):
        single = scorer.score(flow)
        assert batch["predicted_class"] == single["predicted_class"]
        assert np.isclose(batch["attack_probability"], single["attack_probability"], atol=1e-5)
        assert np.isclose(batch["anomaly_score"], single["anomaly_score"], atol=1e-6)


# --- API ---

def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200 and r.json() == {"status": "ok"}


def test_predict_returns_class_and_technique(client):
    s = SAMPLES["PortScan"]
    r = client.post("/predict", json={"features": s["features"], "destination_port": s["destination_port"]})
    assert r.status_code == 200
    body = r.json()
    assert body["is_alert"] and body["predicted_class"] == "PortScan" and body["mitre"]["id"] == "T1046"


def test_missing_feature_is_rejected(client):
    features = {k: v for k, v in SAMPLES["Benign"]["features"].items() if k != "Flow Duration"}
    assert client.post("/predict", json={"features": features}).status_code == 422


def test_invalid_port_is_rejected(client):
    body = {"features": SAMPLES["Benign"]["features"], "destination_port": 70000}
    assert client.post("/predict", json=body).status_code == 422
