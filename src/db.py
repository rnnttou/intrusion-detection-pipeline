import os

import psycopg2
from psycopg2.extras import execute_values

DEFAULT_URL = "postgresql://ids:ids@localhost:5434/ids"

SCHEMA = """
CREATE TABLE IF NOT EXISTS detections (
    id              BIGSERIAL PRIMARY KEY,
    received_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    dst_port        INTEGER,
    predicted_class TEXT NOT NULL,
    attack_proba    DOUBLE PRECISION NOT NULL,
    anomaly_score   DOUBLE PRECISION NOT NULL,
    is_alert        BOOLEAN NOT NULL,
    detector        TEXT,
    mitre_id        TEXT,
    true_family     TEXT,
    true_label      TEXT,
    latency_ms      DOUBLE PRECISION NOT NULL,
    model_version   TEXT NOT NULL
);
"""

INSERT = ("INSERT INTO detections (dst_port, predicted_class, attack_proba, anomaly_score, is_alert, "
          "detector, mitre_id, true_family, true_label, latency_ms, model_version) VALUES %s")


def get_conn():
    conn = psycopg2.connect(os.environ.get("DATABASE_URL", DEFAULT_URL), connect_timeout=3)
    conn.autocommit = True
    return conn


def init_db(conn):
    with conn.cursor() as cur:
        cur.execute(SCHEMA)


def save_detections(conn, rows):
    """Enregistre un lot en une seule requête. rows : liste de (dst_port, result, true_family, true_label)."""
    if not rows:
        return
    values = [
        (port, r["predicted_class"], r["attack_probability"], r["anomaly_score"], r["is_alert"],
         r["detector"], r["mitre"]["id"] if r["mitre"] else None, family, label,
         r["latency_ms"], r["model_version"])
        for port, r, family, label in rows
    ]
    with conn.cursor() as cur:
        execute_values(cur, INSERT, values, page_size=len(values))
