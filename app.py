from __future__ import annotations

import os
import threading
import time
from collections import deque
from pathlib import Path
from typing import Any

from flask import Flask, jsonify, render_template, request
from werkzeug.middleware.proxy_fix import ProxyFix

from anomaly_model import load_model
from audit_ledger import SQLiteAuditLedger
from object_vault import LocalObjectVault
from security_monitor import RequestMonitor

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 32 * 1024
database_path = Path(os.environ.get("SENTINEL_DB", str(Path(app.instance_path) / "sentinel-security.sqlite3")))
ANOMALY_MODEL_PATH = os.environ.get("SENTINEL_ANOMALY_MODEL", str(database_path.parent / "anomaly-model.joblib"))
try:
    ANOMALY_MODEL = load_model(ANOMALY_MODEL_PATH)
except (OSError, ValueError, EOFError) as error:
    raise RuntimeError(f"Could not load Sentinel anomaly model at {ANOMALY_MODEL_PATH}: {error}") from error
app.config["SECURITY_MONITOR"] = RequestMonitor(
    database_path,
    rate_limit=int(os.environ.get("SENTINEL_RATE_LIMIT", "60")),
    rate_window_seconds=int(os.environ.get("SENTINEL_RATE_WINDOW", "10")),
    block_seconds=int(os.environ.get("SENTINEL_BLOCK_SECONDS", "60")),
    anomaly_model=ANOMALY_MODEL,
)
app.config["AUDIT_LEDGER"] = SQLiteAuditLedger(os.environ.get("SENTINEL_AUDIT_DB", str(database_path.parent / "audit.sqlite3")))
app.config["OBJECT_VAULT"] = None
if os.environ.get("MINIO_ENDPOINT"):
    try:
        app.config["OBJECT_VAULT"] = LocalObjectVault(
            internal_endpoint=os.environ["MINIO_ENDPOINT"],
            public_endpoint=os.environ.get("MINIO_PUBLIC_ENDPOINT", os.environ["MINIO_ENDPOINT"]),
            access_key=os.environ["MINIO_ACCESS_KEY"],
            secret_key=os.environ["MINIO_SECRET_KEY"],
            bucket=os.environ.get("MINIO_BUCKET", "sentinel-vault"),
        )
    except KeyError as error:
        raise RuntimeError(f"Missing required MinIO configuration: {error.args[0]}") from error

# ProxyFix is enabled only in Compose, where Flask is not directly published and
# Nginx overwrites X-Forwarded-For with the observed peer address.
if os.environ.get("SENTINEL_TRUST_PROXY") == "1":
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=0, x_host=0, x_port=0, x_prefix=0)

_traffic: deque[float] = deque()
_traffic_lock = threading.Lock()
_RATE_WINDOW_SECONDS = 10
_RATE_LIMIT = 12
_AUDIT_DETAIL_KEYS = {
    "encrypt": {"name", "bytes", "sha256", "merkle_root"},
    "decrypt": {"name", "bytes", "sha256", "merkle_root"},
    "integrity-check": {"name", "bytes", "result", "merkle_root"},
    "shield-test": {"submitted", "allowed", "simulated_blocked"},
    "recovery": {"current", "backup", "result", "merkle_root"},
    "cloud-upload": {"name", "bytes", "result"},
}


def _request_signal() -> str:
    parts = [
        request.path,
        request.query_string.decode("latin-1", errors="replace"),
        request.headers.get("User-Agent", ""),
        request.headers.get("Referer", ""),
    ]
    if request.mimetype in {"application/json", "application/x-www-form-urlencoded"}:
        parts.append(request.get_data(cache=True, as_text=True))
    return "\n".join(parts)[:65536]


@app.before_request
def inspect_incoming_request():
    """Apply the real HTTP-layer monitor before routing to application handlers."""
    decision = app.config["SECURITY_MONITOR"].inspect(
        source_ip=request.remote_addr or "unknown",
        method=request.method,
        path=request.url_rule.rule if request.url_rule else "<unmatched>",
        signal=_request_signal(),
    )
    if decision["action"] == "blocked":
        response = jsonify({
            "error": "Request blocked by the Sentinel HTTP shield",
            "rule": decision["rule"],
            "retry_after_seconds": decision["retry_after"],
        })
        response.status_code = decision["status"]
        response.headers["Retry-After"] = str(decision["retry_after"])
        return response
    return None


@app.after_request
def add_browser_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
        "connect-src 'self' https: blob:; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'"
    )
    return response


def _append_audit_event(event_type: str, details: dict[str, Any]) -> dict[str, Any]:
    """Append to persistent single-host hash-linked audit storage."""
    return app.config["AUDIT_LEDGER"].append(event_type, details)


@app.get("/")
def index():
    return render_template("index.html")


@app.get("/api/health")
def health():
    db_path = Path(app.config["SECURITY_MONITOR"].database)
    return jsonify({
        "status": "ok",
        "service": "Sentinel defensive prototype",
        "monitor": "http-layer",
        "security_database": "available" if db_path.is_file() and os.access(db_path, os.R_OK | os.W_OK) else "unavailable",
        "audit_chain_valid": app.config["AUDIT_LEDGER"].verify(),
        "anomaly_model": ANOMALY_MODEL.get("source") if ANOMALY_MODEL else None,
    })


@app.get("/api/security/metrics")
def security_metrics():
    metrics = app.config["SECURITY_MONITOR"].metrics()
    metrics["packet_sensor"] = "offline/live CLI optional"
    return jsonify(metrics)


@app.get("/api/security/events")
def security_events():
    return jsonify({"events": app.config["SECURITY_MONITOR"].events()})


@app.get("/api/audit")
def audit_events():
    ledger = app.config["AUDIT_LEDGER"]
    return jsonify({"events": ledger.events(50), "valid": ledger.verify()})


@app.get("/api/audit/checkpoint")
def audit_checkpoint():
    return jsonify(app.config["AUDIT_LEDGER"].checkpoint())


@app.get("/api/vault")
def vault_status():
    return jsonify({"enabled": app.config.get("OBJECT_VAULT") is not None, "provider": "local MinIO"})


@app.get("/api/vault/objects")
def vault_objects():
    vault = app.config.get("OBJECT_VAULT")
    if vault is None:
        return jsonify({"error": "Local encrypted-object storage is not configured."}), 503
    return jsonify({"objects": vault.list_objects()})


@app.post("/api/vault/upload-urls")
def vault_upload_urls():
    vault = app.config.get("OBJECT_VAULT")
    if vault is None:
        return jsonify({"error": "Local encrypted-object storage is not configured."}), 503
    data = request.get_json(silent=True) or {}
    name = data.get("name")
    if not isinstance(name, str):
        return jsonify({"error": "name must be a .sentinel filename"}), 400
    try:
        urls = vault.create_upload_urls(name)
    except ValueError as error:
        return jsonify({"error": str(error)}), 400
    return jsonify(urls)


@app.get("/api/vault/objects/<object_id>/download-urls")
def vault_download_urls(object_id: str):
    vault = app.config.get("OBJECT_VAULT")
    if vault is None:
        return jsonify({"error": "Local encrypted-object storage is not configured."}), 503
    urls = vault.create_download_urls(object_id)
    if urls is None:
        return jsonify({"error": "Vault object not found."}), 404
    return jsonify(urls)


@app.post("/api/audit")
def create_audit_event():
    data = request.get_json(silent=True) or {}
    event_type = data.get("type")
    details = data.get("details", {})
    if event_type not in {"encrypt", "decrypt", "integrity-check", "shield-test", "recovery", "cloud-upload"}:
        return jsonify({"error": "Unsupported audit event type"}), 400
    if not isinstance(details, dict):
        return jsonify({"error": "details must be an object"}), 400
    # Store only explicitly approved, non-secret metadata fields.
    allowed_keys = _AUDIT_DETAIL_KEYS[event_type]
    safe_details = {
        str(key): str(value)[:120]
        for key, value in list(details.items())[:8]
        if str(key) in allowed_keys
    }
    event = _append_audit_event(event_type, safe_details)
    return jsonify({"event": event, "valid": app.config["AUDIT_LEDGER"].verify()}), 201


@app.post("/api/shield/simulate")
def simulate_shield():
    """Simulate a low-risk request burst; never generates external traffic."""
    data = request.get_json(silent=True) or {}
    try:
        requested = int(data.get("count", 20))
    except (TypeError, ValueError):
        return jsonify({"error": "count must be an integer"}), 400
    if not 1 <= requested <= 50:
        return jsonify({"error": "count must be between 1 and 50"}), 400

    now = time.monotonic()
    with _traffic_lock:
        while _traffic and now - _traffic[0] > _RATE_WINDOW_SECONDS:
            _traffic.popleft()
        current = len(_traffic)
        allowed = min(requested, max(0, _RATE_LIMIT - current))
        blocked = requested - allowed
        _traffic.extend([now] * allowed)
        remaining = max(0, _RATE_LIMIT - len(_traffic))

    _append_audit_event("shield-test", {"submitted": requested, "allowed": allowed, "simulated_blocked": blocked})
    return jsonify({
        "submitted": requested,
        "allowed": allowed,
        "simulated_blocked": blocked,
        "remaining_in_window": remaining,
        "window_seconds": _RATE_WINDOW_SECONDS,
        "limit": _RATE_LIMIT,
        "note": "Local simulation only; no network attack traffic was sent.",
    })


@app.errorhandler(413)
def request_too_large(_error):
    return jsonify({"error": "Request payload is too large"}), 413


if __name__ == "__main__":
    app.run(host=os.environ.get("HOST", "127.0.0.1"), port=int(os.environ.get("PORT", "5000")), debug=False)
