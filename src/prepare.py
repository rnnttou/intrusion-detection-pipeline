"""Nettoie les 8 fichiers CSV de CIC-IDS2017 et écrit data/flows.parquet (une ligne par flux)."""
import glob
import re

import numpy as np
import pandas as pd

from src.features import FAMILIES, FEATURES, PORT

DAYS = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"]


def clean_label(label: str) -> str:
    # "Web Attack \x96 XSS" : le tiret d'origine est mal encodé selon les copies du jeu
    return re.sub(r"\s+", " ", re.sub(r"[^A-Za-z\- ]", " ", label)).strip()


def chrono_split(n: int) -> np.ndarray:
    """60 % / 20 % / 20 % dans l'ordre des lignes (les fichiers suivent l'ordre de capture)."""
    out = np.full(n, "test", dtype=object)
    out[: int(0.6 * n)] = "train"
    out[int(0.6 * n): int(0.8 * n)] = "val"
    return out


def load_file(path: str) -> pd.DataFrame:
    df = pd.read_csv(path, encoding="latin-1", low_memory=False)
    df.columns = df.columns.str.strip()
    df = df.dropna(subset=["Label"])
    df["label"] = df["Label"].map(clean_label)
    df = df[[PORT] + FEATURES + ["label"]]
    df[FEATURES] = df[FEATURES].replace([np.inf, -np.inf], np.nan)
    df = df.dropna().drop_duplicates()  # flux strictement identiques : fréquents dans ce jeu
    df[FEATURES] = df[FEATURES].astype(np.float32)
    df[PORT] = df[PORT].astype(np.int32)
    df["source"] = re.search(r"([A-Za-z\-]+)\.pcap", path).group(1)
    # Split par étiquette à l'intérieur de chaque fichier : chaque attaque dure quelques dizaines de
    # minutes, son début sert à l'entraînement et sa fin au test. Un tirage au hasard mettrait des
    # flux voisins de la même rafale des deux côtés et gonflerait les scores.
    df["split"] = df.groupby("label")["label"].transform(lambda s: chrono_split(len(s)))
    return df


def main():
    files = sorted(glob.glob("data/*.pcap_ISCX.csv"), key=lambda p: DAYS.index(next(d for d in DAYS if d in p)))
    df = pd.concat([load_file(f) for f in files], ignore_index=True)
    df["family"] = df["label"].map(FAMILIES)
    assert df["family"].notna().all(), df.loc[df["family"].isna(), "label"].unique()
    df.loc[df["family"] == "Unseen", "split"] = "unseen"
    df.to_parquet("data/flows.parquet", index=False)
    print(f"{len(df):,} flux")
    print(df.groupby(["family", "split"]).size().unstack(fill_value=0).to_string())


if __name__ == "__main__":
    main()
