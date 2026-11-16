import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent))

import pandas as pd
import streamlit as st

from src import db
from src.mitre import MITRE, url

st.set_page_config(page_title="Intrusion detection", layout="wide")
st.title("Détection d'intrusions réseau en temps réel")


@st.cache_data(ttl=5)
def recent_detections(limit=20000):
    conn = db.get_conn()
    try:
        return pd.read_sql(
            "SELECT id, received_at, dst_port, predicted_class, attack_proba, anomaly_score, is_alert, "
            f"detector, mitre_id, true_family, true_label, latency_ms FROM detections ORDER BY id DESC LIMIT {limit}",
            conn)
    finally:
        conn.close()


try:
    df = recent_detections()
except Exception as exc:
    st.error(f"PostgreSQL indisponible : {exc}")
    st.stop()

if df.empty:
    st.info("Aucun flux pour l'instant : lancez le consumer puis le producer.")
    st.stop()

alerts = df[df["is_alert"]]
c1, c2, c3, c4 = st.columns(4)
c1.metric("Flux analysés", f"{len(df):,}")
c2.metric("Alertes", f"{len(alerts):,}")
c3.metric("Attaques connues (XGBoost)", f"{int((alerts['detector'] == 'xgboost').sum()):,}")
c4.metric("Anomalies (Isolation Forest)", f"{int((alerts['detector'] == 'iforest').sum()):,}")

left, right = st.columns(2)
with left:
    st.subheader("Alertes par technique MITRE ATT&CK")
    by_technique = alerts.dropna(subset=["mitre_id"]).groupby(["mitre_id", "predicted_class"]).size().reset_index(name="alertes")
    by_technique["technique"] = by_technique["predicted_class"].map(lambda c: MITRE[c]["name"])
    by_technique["tactique"] = by_technique["predicted_class"].map(lambda c: MITRE[c]["tactic"])
    by_technique["lien"] = by_technique["mitre_id"].map(url)
    st.dataframe(
        by_technique.sort_values("alertes", ascending=False)[["mitre_id", "technique", "tactique", "alertes", "lien"]],
        column_config={"lien": st.column_config.LinkColumn("fiche ATT&CK", display_text="ouvrir")},
        hide_index=True, width="stretch")
with right:
    st.subheader("Flux par minute")
    per_minute = df.set_index("received_at").resample("1min")["is_alert"].agg(["size", "sum"])
    st.line_chart(per_minute.rename(columns={"size": "flux", "sum": "alertes"}))

# Qualité mesurée en direct grâce aux vraies étiquettes rejouées avec les flux
labelled = df.dropna(subset=["true_family"])
if not labelled.empty:
    st.subheader("Détection par famille d'attaque (vraies étiquettes du rejeu)")
    rows = []
    for family, part in labelled.groupby("true_family"):
        rows.append({
            "famille réelle": family,
            "flux": len(part),
            "signalés": int(part["is_alert"].sum()),
            "part signalée (%)": round(100 * part["is_alert"].mean(), 1),
            "par XGBoost": int((part["detector"] == "xgboost").sum()),
            "par Isolation Forest": int((part["detector"] == "iforest").sum()),
        })
    table = pd.DataFrame(rows).sort_values("flux", ascending=False)
    st.dataframe(table, hide_index=True, width="stretch")
    benign = labelled[labelled["true_family"] == "Benign"]
    if len(benign):
        st.caption(f"Ligne Benign = fausses alertes : {100 * benign['is_alert'].mean():.2f} % du trafic normal. "
                   "Ligne Unseen = attaques jamais montrées à l'entraînement (Infiltration, Heartbleed).")

st.subheader("Dernières alertes")
st.dataframe(
    alerts[["received_at", "dst_port", "predicted_class", "mitre_id", "detector", "attack_proba",
            "anomaly_score", "true_label"]].head(100),
    hide_index=True, width="stretch")
