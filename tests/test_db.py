import pytest

from src import db
from src.mitre import MITRE


def result(family, detector):
    return {"predicted_class": family, "attack_probability": 0.9, "anomaly_score": 0.4, "is_alert": detector is not None,
            "detector": detector, "mitre": MITRE.get(family), "latency_ms": 1.0, "model_version": "test-batch"}


@pytest.fixture
def conn():
    try:
        c = db.get_conn()
    except Exception:
        pytest.skip("PostgreSQL indisponible")
    db.init_db(c)
    yield c
    with c.cursor() as cur:
        cur.execute("DELETE FROM detections WHERE model_version = 'test-batch'")
    c.close()


def test_batch_insert_keeps_every_row(conn):
    rows = [(80, result("DDoS", "xgboost"), "DDoS", "DDoS"),
            (444, result("Inconnu", "iforest"), "Unseen", "Heartbleed"),
            (None, result("Benign", None), None, None)]
    db.save_detections(conn, rows)
    db.save_detections(conn, [])  # un lot vide ne fait rien
    with conn.cursor() as cur:
        cur.execute("SELECT dst_port, predicted_class, is_alert, detector, mitre_id, true_label "
                    "FROM detections WHERE model_version = 'test-batch' ORDER BY id")
        saved = cur.fetchall()
    assert saved == [(80, "DDoS", True, "xgboost", "T1498", "DDoS"),
                     (444, "Inconnu", True, "iforest", None, "Heartbleed"),
                     (None, "Benign", False, None, None, None)]
