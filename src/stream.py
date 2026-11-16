import pandas as pd

from src.features import FEATURES, PORT


def load_stream(path="data/flows.parquet", attack_share=None, seed=42) -> pd.DataFrame:
    """Flux du test (+ les attaques jamais vues), mélangés.

    Dans le jeu d'origine chaque attaque arrive en bloc ; on mélange pour que le rejeu
    montre toutes les familles dès les premières secondes.
    """
    df = pd.read_parquet(path, filters=[("split", "in", ["test", "unseen"])])
    if attack_share is not None:  # règle la part d'attaques (16,5 % dans le test)
        attacks = df[df["family"] != "Benign"]
        n_benign = int(len(attacks) * (1 - attack_share) / attack_share)
        benign = df[df["family"] == "Benign"]
        df = pd.concat([attacks, benign.sample(min(n_benign, len(benign)), random_state=seed)])
    return df.sample(frac=1, random_state=seed)[[PORT] + FEATURES + ["family", "label"]]
