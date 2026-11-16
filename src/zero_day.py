"""Simule des attaques jamais vues : on cache une famille à l'entraînement, puis on regarde
si chaque détecteur la signale quand même sur le test.

L'Isolation Forest n'apprend que du trafic normal : toute attaque est « jamais vue » pour lui.
XGBoost est réentraîné 6 fois, une fois par famille cachée.
"""
import json

import pandas as pd

from src.evaluate import ANOMALY_FPR, ATTACK_FPR, anomaly_score, load_models, threshold_for_fpr
from src.features import CLASSES, build_features
from src.train import fit_xgb, sample_benign

BENIGN_TRAIN = 150_000  # plus petit que pour le modèle final : 6 entraînements


def main():
    df = pd.read_parquet("data/flows.parquet")
    train, val, test = (df[df["split"] == s] for s in ("train", "val", "test"))
    benign_val = build_features(val[val["family"] == "Benign"])
    _, iforest = load_models()
    thr_anomaly = threshold_for_fpr(anomaly_score(iforest, benign_val), ANOMALY_FPR)
    benign_train = sample_benign(train, BENIGN_TRAIN)

    rows = []
    for hidden in CLASSES[1:]:
        classes = [c for c in CLASSES if c != hidden]
        keep = lambda part: part[part["family"].isin(classes)]
        model = fit_xgb(pd.concat([benign_train, keep(train[train["family"] != "Benign"])]), keep(val),
                        classes=classes, verbose=False)
        thr = threshold_for_fpr(1 - model.predict_proba(benign_val)[:, 0], ATTACK_FPR)
        X = build_features(test[test["family"] == hidden])
        rows.append({
            "hidden_family": hidden,
            "test_flows": len(X),
            "xgboost_detects": float((1 - model.predict_proba(X)[:, 0] >= thr).mean()),
            "iforest_detects": float((anomaly_score(iforest, X) >= thr_anomaly).mean()),
        })
        print(rows[-1], flush=True)
    with open("reports/zero_day.json", "w") as f:
        json.dump(rows, f, indent=2)
    print(pd.DataFrame(rows).round(3).to_string(index=False))


if __name__ == "__main__":
    main()
