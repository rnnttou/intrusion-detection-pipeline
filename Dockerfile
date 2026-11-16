FROM python:3.11-slim
WORKDIR /app
# sans tampon : les print() apparaissent tout de suite dans docker compose logs
ENV PYTHONUNBUFFERED=1
# xgboost a besoin d'OpenMP (absent de l'image slim)
RUN apt-get update && apt-get install -y --no-install-recommends libgomp1 \
    && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY src/ src/
COPY models/ models/
COPY reports/metrics.json reports/metrics.json
