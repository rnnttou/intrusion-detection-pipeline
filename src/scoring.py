import json
import time

import joblib
import pandas as pd
from xgboost import XGBClassifier

from src.features import CLASSES, build_features
from src.mitre import technique

UNKNOWN = "Inconnu"


class IntrusionScorer:
    """Deux détecteurs en série : XGBoost reconnaît les attaques connues, l'Isolation Forest
    signale ce qui ne ressemble pas au trafic normal."""

    def __init__(self, model_path="models/model.json", iforest_path="models/iforest.joblib",
                 metrics_path="reports/metrics.json"):
        self.model = XGBClassifier()
        self.model.load_model(model_path)
        self.iforest = joblib.load(iforest_path)
        self.iforest.n_jobs = 1  # un lot en service est petit : lancer des threads coûte plus qu'il ne rapporte
        with open(metrics_path) as f:
            thresholds = json.load(f)["thresholds"]
        self.thr_attack, self.thr_anomaly = thresholds["attack_proba"], thresholds["anomaly_score"]
        self.version = "ids-v1"

    def score_many(self, flows: list) -> list:
        """Note un lot en un seul appel par modèle. latency_ms = temps du lot / taille."""
        start = time.perf_counter()
        X = build_features(pd.DataFrame(flows))
        proba = self.model.predict_proba(X)
        attack_proba = 1 - proba[:, 0]
        best_attack = proba[:, 1:].argmax(axis=1) + 1  # meilleure classe d'attaque, même si Benign domine
        anomaly = -self.iforest.score_samples(X)
        latency = (time.perf_counter() - start) * 1000 / len(flows)

        results = []
        for p, k, a in zip(attack_proba, best_attack, anomaly):
            if p >= self.thr_attack:
                family, detector, severity = CLASSES[k], "xgboost", "haute"
            elif a >= self.thr_anomaly:
                family, detector, severity = UNKNOWN, "iforest", "basse"
            else:
                family, detector, severity = "Benign", None, None
            results.append({
                "predicted_class": family,
                "attack_probability": float(p),
                "anomaly_score": float(a),
                "is_alert": detector is not None,
                "detector": detector,
                "severity": severity,
                "mitre": technique(family),
                "model_version": self.version,
                "latency_ms": latency,
            })
        return results

    def score(self, flow: dict) -> dict:
        return self.score_many([flow])[0]
