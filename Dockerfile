FROM python:3.12.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=5000 \
    SENTINEL_DB=/data/sentinel-security.sqlite3 \
    SENTINEL_ANOMALY_MODEL=/data/anomaly-model.joblib
WORKDIR /app
RUN useradd --create-home --uid 10001 sentinel
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN mkdir -p /data /app/instance && chown -R sentinel:sentinel /data /app/instance
USER sentinel
EXPOSE 5000
CMD ["waitress-serve", "--listen=0.0.0.0:5000", "app:app"]
