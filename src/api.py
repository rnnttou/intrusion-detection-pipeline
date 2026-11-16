import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from pydantic import BaseModel, Field, field_validator

from src import db
from src.features import FEATURES
from src.scoring import IntrusionScorer


class Flow(BaseModel):
    features: dict[str, float] = Field(description="les 76 mesures CICFlowMeter du flux")
    destination_port: int | None = Field(default=None, ge=0, le=65535)

    @field_validator("features")
    @classmethod
    def all_features_present(cls, value):
        missing = [name for name in FEATURES if name not in value]
        if missing:
            raise ValueError(f"mesures manquantes : {missing[:5]}{'...' if len(missing) > 5 else ''}")
        return value


class Technique(BaseModel):
    id: str
    name: str
    tactic: str


class Detection(BaseModel):
    predicted_class: str
    attack_probability: float
    anomaly_score: float
    is_alert: bool
    detector: str | None
    severity: str | None
    mitre: Technique | None
    model_version: str
    latency_ms: float


log = logging.getLogger("api")
state = {}


@asynccontextmanager
async def lifespan(app: FastAPI):
    state["scorer"] = IntrusionScorer()  # chargé une seule fois
    try:
        state["conn"] = db.get_conn()
        db.init_db(state["conn"])
    except Exception as exc:  # Postgres éteint : l'API continue sans enregistrer
        log.warning("PostgreSQL indisponible, détections non enregistrées (%s)", exc)
        state["conn"] = None
    yield
    if state.get("conn"):
        state["conn"].close()
    state.clear()


app = FastAPI(title="Intrusion detection API", lifespan=lifespan)


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/predict", response_model=Detection)
def predict(flow: Flow):
    result = state["scorer"].score(flow.features)
    if state.get("conn"):
        try:
            db.save_detections(state["conn"], [(flow.destination_port, result, None, None)])
        except Exception as exc:
            log.warning("échec d'enregistrement de la détection (%s)", exc)
    return result
