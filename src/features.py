import numpy as np
import pandas as pd

# 76 mesures par flux réseau, calculées par CICFlowMeter. Deux colonnes du jeu d'origine sont
# écartées : "Fwd Header Length.1" (doublon) et "Destination Port" (le modèle apprendrait
# « port 80 = attaque » au lieu du comportement du flux ; le port reste affiché dans l'alerte).
FEATURES = [
    "Flow Duration", "Total Fwd Packets", "Total Backward Packets", "Total Length of Fwd Packets",
    "Total Length of Bwd Packets", "Fwd Packet Length Max", "Fwd Packet Length Min",
    "Fwd Packet Length Mean", "Fwd Packet Length Std", "Bwd Packet Length Max", "Bwd Packet Length Min",
    "Bwd Packet Length Mean", "Bwd Packet Length Std", "Flow Bytes/s", "Flow Packets/s", "Flow IAT Mean",
    "Flow IAT Std", "Flow IAT Max", "Flow IAT Min", "Fwd IAT Total", "Fwd IAT Mean", "Fwd IAT Std",
    "Fwd IAT Max", "Fwd IAT Min", "Bwd IAT Total", "Bwd IAT Mean", "Bwd IAT Std", "Bwd IAT Max",
    "Bwd IAT Min", "Fwd PSH Flags", "Bwd PSH Flags", "Fwd URG Flags", "Bwd URG Flags", "Fwd Header Length",
    "Bwd Header Length", "Fwd Packets/s", "Bwd Packets/s", "Min Packet Length", "Max Packet Length",
    "Packet Length Mean", "Packet Length Std", "Packet Length Variance", "FIN Flag Count", "SYN Flag Count",
    "RST Flag Count", "PSH Flag Count", "ACK Flag Count", "URG Flag Count", "CWE Flag Count",
    "ECE Flag Count", "Down/Up Ratio", "Average Packet Size", "Avg Fwd Segment Size",
    "Avg Bwd Segment Size", "Fwd Avg Bytes/Bulk", "Fwd Avg Packets/Bulk", "Fwd Avg Bulk Rate",
    "Bwd Avg Bytes/Bulk", "Bwd Avg Packets/Bulk", "Bwd Avg Bulk Rate", "Subflow Fwd Packets",
    "Subflow Fwd Bytes", "Subflow Bwd Packets", "Subflow Bwd Bytes", "Init_Win_bytes_forward",
    "Init_Win_bytes_backward", "act_data_pkt_fwd", "min_seg_size_forward", "Active Mean", "Active Std",
    "Active Max", "Active Min", "Idle Mean", "Idle Std", "Idle Max", "Idle Min",
]
PORT = "Destination Port"

# Les 15 étiquettes d'origine regroupées en familles d'attaque.
FAMILIES = {
    "BENIGN": "Benign",
    "DoS Hulk": "DoS", "DoS GoldenEye": "DoS", "DoS slowloris": "DoS", "DoS Slowhttptest": "DoS",
    "DDoS": "DDoS",
    "PortScan": "PortScan",
    "FTP-Patator": "BruteForce", "SSH-Patator": "BruteForce",
    "Web Attack Brute Force": "WebAttack", "Web Attack XSS": "WebAttack", "Web Attack Sql Injection": "WebAttack",
    "Bot": "Bot",
    # Trop rares pour être apprises (36 et 11 flux) : jamais montrées au modèle supervisé,
    # elles servent d'attaques « jamais vues » pour évaluer la détection d'anomalies.
    "Infiltration": "Unseen", "Heartbleed": "Unseen",
}
CLASSES = ["Benign", "DoS", "DDoS", "PortScan", "BruteForce", "WebAttack", "Bot"]  # ordre = sortie du modèle


def build_features(df: pd.DataFrame) -> np.ndarray:
    """Même transformation à l'entraînement et en service : colonnes dans l'ordre, valeurs finies."""
    X = df[FEATURES].to_numpy(np.float32)
    # Flow Bytes/s et Flow Packets/s valent inf quand la durée du flux est nulle
    return np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)
