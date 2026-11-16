"""Entraîne les deux détecteurs : XGBoost (attaques connues) et Isolation Forest (anomalies)."""
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import f1_score
from xgboost import XGBClassifier

from src.features import CLASSES, build_features

BENIGN_TRAIN = 500_000  # flux normaux gardés pour XGBoost (sur 1,29 million) : divise le temps d'entraînement
IFOREST_TRAIN = 200_000


def fit_xgb(train: pd.DataFrame, val: pd.DataFrame, classes=CLASSES, verbose=50) -> XGBClassifier:
    """Partagée avec src.zero_day, qui réentraîne en cachant une famille d'attaque."""
    y_train = train["family"].map(classes.index).to_numpy()
    y_val = val["family"].map(classes.index).to_numpy()
    # poids inversement proportionnels à la fréquence, plafonnés : Bot (1 168 flux) compte autant
    # que possible sans que quelques flux mal étiquetés dominent
    counts = np.bincount(y_train, minlength=len(classes))
    weights = np.minimum(counts.max() / counts, 50.0)[y_train]
    model = XGBClassifier(
        n_estimators=600, learning_rate=0.1, max_depth=6, subsample=0.8, colsample_bytree=0.8,
        objective="multi:softprob", eval_metric="mlogloss", early_stopping_rounds=30,
        tree_method="hist", random_state=42,
    )
    model.fit(build_features(train), y_train, sample_weight=weights,
              eval_set=[(build_features(val), y_val)], verbose=verbose)
    return model


def sample_benign(train: pd.DataFrame, n: int, seed=42) -> pd.DataFrame:
    benign = train[train["family"] == "Benign"]
    return benign.sample(min(n, len(benign)), random_state=seed)


def main():
    df = pd.read_parquet("data/flows.parquet")
    train, val = df[df["split"] == "train"], df[df["split"] == "val"]
    Path("models").mkdir(exist_ok=True)

    start = time.perf_counter()
    xgb_train = pd.concat([sample_benign(train, BENIGN_TRAIN), train[train["family"] != "Benign"]])
    model = fit_xgb(xgb_train, val)
    pred = model.predict(build_features(val))
    y_val = val["family"].map(CLASSES.index).to_numpy()
    print(f"XGBoost : {model.best_iteration + 1} tours, {time.perf_counter() - start:.0f} s, "
          f"macro-F1 validation {f1_score(y_val, pred, average='macro'):.4f}")
    model.save_model("models/model.json")

    # Isolation Forest : entraîné sur du trafic normal uniquement, sans aucune étiquette d'attaque
    start = time.perf_counter()
    iforest = IsolationForest(n_estimators=200, max_samples=512, random_state=42, n_jobs=-1)
    iforest.fit(build_features(sample_benign(train, IFOREST_TRAIN)))
    print(f"Isolation Forest : {time.perf_counter() - start:.0f} s")
    joblib.dump(iforest, "models/iforest.joblib", compress=3)


if __name__ == "__main__":
    main()
