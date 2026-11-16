"""Mesure les deux détecteurs sur le test et fixe les seuils d'alerte sur la validation."""
import json
from pathlib import Path

import joblib
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.metrics import ConfusionMatrixDisplay, classification_report, roc_auc_score
from xgboost import XGBClassifier

from src.features import CLASSES, build_features

ATTACK_FPR = 0.001   # au plus 1 fausse alerte pour 1 000 flux normaux (détecteur d'attaques connues)
ANOMALY_FPR = 0.01   # au plus 1 pour 100 (détecteur d'anomalies, alertes de priorité basse)


def threshold_for_fpr(benign_scores, fpr):
    """Seuil tel qu'une part `fpr` des flux normaux le dépasse."""
    return float(np.quantile(benign_scores, 1 - fpr))


def anomaly_score(iforest, X):
    return -iforest.score_samples(X)  # plus c'est haut, plus le flux est inhabituel


def load_models():
    model = XGBClassifier()
    model.load_model("models/model.json")
    return model, joblib.load("models/iforest.joblib")


def main():
    df = pd.read_parquet("data/flows.parquet")
    val, test, unseen = (df[df["split"] == s] for s in ("val", "test", "unseen"))
    model, iforest = load_models()
    X_val, X_test = build_features(val), build_features(test)
    y_test = test["family"].map(CLASSES.index).to_numpy()
    benign_val, benign_test = (val["family"] == "Benign").to_numpy(), y_test == 0

    # Seuils choisis sur la validation, jamais sur le test
    thr_attack = threshold_for_fpr(1 - model.predict_proba(X_val[benign_val])[:, 0], ATTACK_FPR)
    thr_anomaly = threshold_for_fpr(anomaly_score(iforest, X_val[benign_val]), ANOMALY_FPR)

    proba = model.predict_proba(X_test)
    attack_proba, pred = 1 - proba[:, 0], proba.argmax(axis=1)
    anomaly = anomaly_score(iforest, X_test)
    xgb_alert, if_alert = attack_proba >= thr_attack, anomaly >= thr_anomaly

    report = classification_report(y_test, pred, target_names=CLASSES, output_dict=True, digits=4)
    print(classification_report(y_test, pred, target_names=CLASSES, digits=4))

    per_family = {}
    for i, name in enumerate(CLASSES[1:], start=1):
        mask = y_test == i
        per_family[name] = {
            "test_flows": int(mask.sum()),
            "precision": report[name]["precision"],
            "recall": report[name]["recall"],
            "detected_by_xgboost": float(xgb_alert[mask].mean()),
            "detected_by_iforest": float(if_alert[mask].mean()),
        }
    X_unseen = build_features(unseen)
    unseen_xgb = 1 - model.predict_proba(X_unseen)[:, 0] >= thr_attack
    unseen_if = anomaly_score(iforest, X_unseen) >= thr_anomaly
    results = {
        "thresholds": {"attack_proba": thr_attack, "anomaly_score": thr_anomaly},
        "macro_f1_test": report["macro avg"]["f1-score"],
        "accuracy_test": report["accuracy"],
        "false_alerts_per_100k_benign": {
            "xgboost": float(1e5 * xgb_alert[benign_test].mean()),
            "iforest": float(1e5 * if_alert[benign_test].mean()),
            "either": float(1e5 * (xgb_alert | if_alert)[benign_test].mean()),
        },
        "attack_recall_test": {
            "xgboost": float(xgb_alert[~benign_test].mean()),
            "iforest": float(if_alert[~benign_test].mean()),
            "either": float((xgb_alert | if_alert)[~benign_test].mean()),
        },
        "iforest_roc_auc_test": float(roc_auc_score(~benign_test, anomaly)),
        "per_family": per_family,
        "never_trained_on": {  # Infiltration et Heartbleed : aucun des deux modèles ne les a vues
            "flows": int(len(unseen)),
            "by_label": {
                label: {"flows": int(m.sum()), "xgboost": int(unseen_xgb[m].sum()), "iforest": int(unseen_if[m].sum()),
                        "either": int((unseen_xgb | unseen_if)[m].sum())}
                for label in unseen["label"].unique() for m in [(unseen["label"] == label).to_numpy()]
            },
        },
    }
    Path("reports").mkdir(exist_ok=True)
    with open("reports/metrics.json", "w") as f:
        json.dump(results, f, indent=2)
    print(json.dumps({k: v for k, v in results.items() if k != "per_family"}, indent=2))
    print(pd.DataFrame(per_family).T.round(4).to_string())

    fig, ax = plt.subplots(figsize=(7.5, 6.5))
    ConfusionMatrixDisplay.from_predictions(y_test, pred, display_labels=CLASSES, normalize="true",
                                            values_format=".2f", xticks_rotation=45, ax=ax, colorbar=False)
    ax.set_title("XGBoost sur le test (part de chaque classe réelle)")
    ax.set_xlabel("Classe prédite"); ax.set_ylabel("Classe réelle")
    fig.tight_layout(); fig.savefig("reports/confusion_matrix.png", dpi=120)


if __name__ == "__main__":
    main()
