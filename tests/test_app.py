import os
import tempfile
import uuid
from pathlib import Path

import pytest

_test_data_root = tempfile.TemporaryDirectory(prefix=f"sentinel-tests-{uuid.uuid4().hex}-")
os.environ["SENTINEL_DB"] = str(Path(_test_data_root.name) / "security.sqlite3")
os.environ["SENTINEL_AUDIT_DB"] = str(Path(_test_data_root.name) / "audit.sqlite3")
os.environ["SENTINEL_ANOMALY_MODEL"] = str(Path(_test_data_root.name) / "missing-model.joblib")

import app as sentinel
from security_monitor import RequestMonitor
from audit_ledger import SQLiteAuditLedger


def setup_function():
    sentinel._traffic.clear()


def test_health_endpoint(client):
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json["status"] == "ok"
    assert response.json["monitor"] == "http-layer"
    assert response.json["security_database"] == "available"
    assert response.json["audit_chain_valid"] is True
    assert response.headers["X-Content-Type-Options"] == "nosniff"


def test_dashboard_renders_demo_labels(client):
    response = client.get("/")
    assert response.status_code == 200
    assert b"Traffic shield" in response.data
    assert b"DEMONSTRATION" in response.data


def test_vault_is_explicitly_disabled_without_minio(client, monkeypatch):
    monkeypatch.setitem(sentinel.app.config, "OBJECT_VAULT", None)
    assert client.get("/api/vault").json == {"enabled": False, "provider": "local MinIO"}
    assert client.get("/api/vault/objects").status_code == 503
    assert client.post("/api/vault/upload-urls", json={"name": "notes.sentinel"}).status_code == 503


def test_vault_upload_urls_only_accept_sentinel_artifacts(client, monkeypatch):
    class FakeVault:
        def create_upload_urls(self, name):
            if not name.endswith(".sentinel"):
                raise ValueError("name must be a filename ending in .sentinel")
            return {"object_id": "a" * 32, "name": name, "file_url": "http://localhost:8080/signed", "manifest_url": "http://localhost:8080/manifest"}

    monkeypatch.setitem(sentinel.app.config, "OBJECT_VAULT", FakeVault())
    invalid = client.post("/api/vault/upload-urls", json={"name": "plaintext.txt"})
    assert invalid.status_code == 400
    valid = client.post("/api/vault/upload-urls", json={"name": "notes.sentinel"})
    assert valid.status_code == 200
    assert valid.json["name"] == "notes.sentinel"
    assert valid.json["object_id"] == "a" * 32


def test_vault_download_urls_validate_ids_and_report_missing_objects(client, monkeypatch):
    class FakeVault:
        def create_download_urls(self, object_id):
            return {"name": "notes.sentinel", "file_url": "http://localhost:8080/signed", "manifest_url": None} if object_id == "a" * 32 else None

    monkeypatch.setitem(sentinel.app.config, "OBJECT_VAULT", FakeVault())
    assert client.get("/api/vault/objects/not-an-id/download-urls").status_code == 404
    assert client.get(f"/api/vault/objects/{'a' * 32}/download-urls").json["name"] == "notes.sentinel"


def test_audit_chain_links_and_validates(client):
    first = client.post("/api/audit", json={"type": "encrypt", "details": {"name": "sample.txt"}})
    second = client.post("/api/audit", json={"type": "decrypt", "details": {"result": "success"}})
    events = client.get("/api/audit").json
    assert first.status_code == 201
    assert second.status_code == 201
    assert events["valid"] is True
    newest, oldest = events["events"]
    assert newest["previous_hash"] == oldest["hash"]


def test_persistent_audit_survives_new_ledger_instance(tmp_path):
    database = tmp_path / "durable-audit.sqlite3"
    first_instance = SQLiteAuditLedger(database)
    first_instance.append("integrity-check", {"file": "sample.sentinel", "result": "ok"})
    reopened = SQLiteAuditLedger(database)
    assert reopened.verify() is True
    assert reopened.events()[0]["type"] == "integrity-check"
    assert reopened.checkpoint()["event_count"] == 1


def test_audit_checkpoint_endpoint_returns_verified_head(client):
    client.post("/api/audit", json={"type": "encrypt", "details": {"name": "evidence.sentinel"}})
    checkpoint = client.get("/api/audit/checkpoint").json
    assert checkpoint["verified"] is True
    assert checkpoint["event_count"] == 1
    assert len(checkpoint["head_hash"]) == 64


def test_audit_ledger_detects_stored_record_tampering(tmp_path):
    import sqlite3

    database = tmp_path / "tamper-audit.sqlite3"
    ledger = SQLiteAuditLedger(database)
    ledger.append("encrypt", {"name": "sample.bin"})
    with sqlite3.connect(database) as connection:
        connection.execute("UPDATE audit_events SET details_json = ? WHERE index_no = 1", ('{"name":"changed.bin"}',))
    assert ledger.verify() is False


def test_sqlite_backup_verifies_and_restores_without_overwriting_live_data(tmp_path):
    from data_backup import create_backup, restore_to_directory, verify_backup

    security_db = tmp_path / "source" / "security.sqlite3"
    audit_db = tmp_path / "source" / "audit.sqlite3"
    RequestMonitor(security_db)
    SQLiteAuditLedger(audit_db).append("integrity-check", {"result": "verified"})
    backup = create_backup({"security.sqlite3": security_db, "audit.sqlite3": audit_db}, tmp_path / "backups")
    assert verify_backup(backup)["valid"] is True
    restored = restore_to_directory(backup, tmp_path / "recovered")
    assert {path.name for path in restored} == {"security.sqlite3", "audit.sqlite3"}
    assert SQLiteAuditLedger(tmp_path / "recovered" / "audit.sqlite3").verify() is True
    with pytest.raises(FileExistsError):
        restore_to_directory(backup, tmp_path / "recovered")


def test_sqlite_backup_refuses_modified_audit_chain(tmp_path):
    import sqlite3

    from data_backup import create_backup

    security_db = tmp_path / "source" / "security.sqlite3"
    audit_db = tmp_path / "source" / "audit.sqlite3"
    RequestMonitor(security_db)
    SQLiteAuditLedger(audit_db).append("encrypt", {"file": "one.sentinel"})
    with sqlite3.connect(audit_db) as connection:
        connection.execute("UPDATE audit_events SET details_json = '{}' WHERE index_no = 1")
    with pytest.raises(ValueError, match="Audit chain verification failed"):
        create_backup({"security.sqlite3": security_db, "audit.sqlite3": audit_db}, tmp_path / "backups")
    assert list((tmp_path / "backups").iterdir()) == []


def test_invalid_audit_type_rejected(client):
    response = client.post("/api/audit", json={"type": "anything", "details": {}})
    assert response.status_code == 400


def test_cloud_upload_event_does_not_accept_url_field(client):
    response = client.post(
        "/api/audit",
        json={"type": "cloud-upload", "details": {"name": "encrypted.sentinel", "result": "complete"}},
    )
    assert response.status_code == 201
    assert response.json["event"]["details"] == {"name": "encrypted.sentinel", "result": "complete"}


def test_audit_event_drops_passphrases_signed_urls_and_unapproved_fields(client):
    response = client.post(
        "/api/audit",
        json={
            "type": "cloud-upload",
            "details": {
                "name": "encrypted.sentinel",
                "result": "complete",
                "presigned_url": "https://storage.example/secret?signature=private",
                "passphrase": "do-not-store-this",
                "file_bytes": "plaintext",
            },
        },
    )
    assert response.status_code == 201
    serialized = str(response.json["event"]["details"])
    assert "signature" not in serialized
    assert "passphrase" not in serialized
    assert "plaintext" not in serialized


def test_simulated_shield_caps_requests(client):
    response = client.post("/api/shield/simulate", json={"count": 20})
    assert response.status_code == 200
    assert response.json["allowed"] == 12
    assert response.json["simulated_blocked"] == 8
    assert "no network attack traffic" in response.json["note"]


def test_simulated_shield_validates_count(client):
    assert client.post("/api/shield/simulate", json={"count": 51}).status_code == 400


def test_http_waf_blocks_xss_signature_and_records_metadata_only(client):
    response = client.get("/search", query_string={"q": "<script>alert(1)</script>"}, environ_base={"REMOTE_ADDR": "198.51.100.10"})
    assert response.status_code == 403
    assert response.json["rule"] == "xss"
    events = sentinel.app.config["SECURITY_MONITOR"].events()
    assert events[0]["action"] == "blocked"
    assert events[0]["path"] == "<unmatched>"
    assert "<script>" not in str(events[0])


@pytest.mark.parametrize(
    ("signal", "expected_rule"),
    [
        ("/search?q=UNION%20SELECT%20password%20FROM%20users", "sql-injection"),
        ("/download?name=..%2F..%2Fsecret", "path-traversal"),
        ("/comment?body=%3Cscript%3Ealert(1)%3C%2Fscript%3E", "xss"),
        ("/run?cmd=%3Bid%20%7C%20bash", "command-injection"),
        ("/.env", "scanner-probe"),
    ],
)
def test_http_signature_rules(signal, expected_rule):
    assert RequestMonitor.classify(signal)[0] == expected_rule


def test_json_body_detection_is_logged_persistently_without_payload(client):
    monitor = sentinel.app.config["SECURITY_MONITOR"]
    response = client.post(
        "/api/audit",
        json={"type": "encrypt", "details": {"note": "<script>secret-payload</script>"}},
        environ_base={"REMOTE_ADDR": "198.51.100.55"},
    )
    assert response.status_code == 403
    events = RequestMonitor(monitor.database).events()
    assert events[0]["rule"] == "xss"
    assert "secret-payload" not in str(events[0])


def test_http_rate_limit_temporarily_blocks_source(client):
    client_ip = "198.51.100.20"
    for _ in range(3):
        assert client.get("/api/health", environ_base={"REMOTE_ADDR": client_ip}).status_code == 200
    blocked = client.get("/api/health", environ_base={"REMOTE_ADDR": client_ip})
    assert blocked.status_code == 429
    assert blocked.json["rule"] == "request-rate"
    assert blocked.headers["Retry-After"]


def test_signature_temporarily_blocks_non_local_source(client):
    client_ip = "198.51.100.40"
    flagged = client.get("/search?q=..%2F..%2Fetc%2Fpasswd", environ_base={"REMOTE_ADDR": client_ip})
    assert flagged.status_code == 403
    blocked = client.get("/api/health", environ_base={"REMOTE_ADDR": client_ip})
    assert blocked.status_code == 429
    assert blocked.json["rule"] == "path-traversal"


def test_loopback_signature_does_not_lock_dashboard(client):
    flagged = client.get("/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E")
    after = client.get("/api/security/metrics")
    assert flagged.status_code == 403
    assert after.status_code == 200
    assert after.json["active_blocks"] == 0


def test_loopback_rate_does_not_lock_dashboard(tmp_path):
    monitor = RequestMonitor(tmp_path / "loopback.sqlite3", rate_limit=1)
    for timestamp in (100, 101, 102):
        result = monitor.inspect(source_ip="127.0.0.1", method="GET", path="/", signal="/", now=timestamp)
    assert result["action"] == "allowed"


def test_isolation_forest_model_trains_saves_loads_and_scores(tmp_path):
    from anomaly_model import load_model, score_window, save_model, synthetic_benign_baseline, train_model

    bundle = train_model(synthetic_benign_baseline(rows=120), source="test-synthetic")
    path = tmp_path / "model.joblib"
    save_model(bundle, path)
    loaded = load_model(path)
    assert loaded is not None
    outcome = score_window(loaded, {
        "requests": 10,
        "unique_sources": 2,
        "unique_routes": 3,
        "blocked_ratio": 0.0,
        "suspicious_events": 0,
        "source_entropy": 0.5,
    })
    assert outcome["model_source"] == "test-synthetic"
    assert isinstance(outcome["anomaly"], bool)


def test_isolation_forest_flags_extreme_traffic_outlier(tmp_path):
    from anomaly_model import load_model, save_model, synthetic_benign_baseline, train_model

    bundle = train_model(synthetic_benign_baseline(rows=300), source="test-synthetic")
    path = tmp_path / "outlier-model.joblib"
    save_model(bundle, path)
    loaded = load_model(path)
    assert loaded is not None
    from anomaly_model import score_window
    result = score_window(loaded, {
        "requests": 100_000,
        "unique_sources": 20_000,
        "unique_routes": 5_000,
        "blocked_ratio": 0.95,
        "suspicious_events": 20_000,
        "source_entropy": 10_000,
    })
    assert result["anomaly"] is True


def test_synthetic_model_accepts_typical_low_volume_window():
    from anomaly_model import score_window, synthetic_benign_baseline, train_model

    model = train_model(synthetic_benign_baseline(rows=600), source="synthetic-demo")
    result = score_window(model, {
        "requests": 5,
        "unique_sources": 1,
        "unique_routes": 2,
        "blocked_ratio": 0,
        "suspicious_events": 0,
        "source_entropy": 0,
    })
    assert result["anomaly"] is False


def test_monitor_model_scores_an_aggregate_window_once(tmp_path):
    from anomaly_model import synthetic_benign_baseline, train_model

    bundle = train_model(synthetic_benign_baseline(rows=200), source="test-synthetic")
    monitor = RequestMonitor(tmp_path / "model-events.sqlite3", rate_limit=100, anomaly_model=bundle)
    for timestamp, source in ((100, "198.51.100.1"), (101, "198.51.100.2"), (102, "198.51.100.3")):
        monitor.inspect(source_ip=source, method="GET", path="/", signal="/", now=timestamp)
    with monitor._connection() as db:
        count = db.execute("SELECT COUNT(*) FROM anomaly_windows").fetchone()[0]
    assert count == 1


def test_model_anomaly_creates_advisory_event_not_block(tmp_path):
    import numpy as np

    class AlwaysAnomaly:
        def decision_function(self, features):
            return np.array([-0.25])

        def predict(self, features):
            return np.array([-1])

    bundle = {"model": AlwaysAnomaly(), "source": "test-model"}
    monitor = RequestMonitor(tmp_path / "advisory-model.sqlite3", anomaly_model=bundle)
    first = monitor.inspect(source_ip="198.51.100.1", method="GET", path="/", signal="/", now=100)
    second = monitor.inspect(source_ip="198.51.100.2", method="GET", path="/", signal="/", now=101)
    assert first["action"] == second["action"] == "allowed"
    assert monitor.events()[0]["rule"] == "ml-anomaly"
    assert monitor.events()[0]["action"] == "alert"


def test_anomaly_model_results_are_deduplicated_under_threads(tmp_path):
    from concurrent.futures import ThreadPoolExecutor

    import numpy as np

    class AlwaysAnomaly:
        def decision_function(self, features):
            return np.array([-0.25])

        def predict(self, features):
            return np.array([-1])

    monitor = RequestMonitor(
        tmp_path / "parallel-model.sqlite3",
        anomaly_model={"model": AlwaysAnomaly(), "source": "test"},
    )
    requests = [(f"198.51.100.{index}", 100 + index % 2) for index in range(12)]
    with ThreadPoolExecutor(max_workers=6) as pool:
        list(pool.map(lambda entry: monitor.inspect(source_ip=entry[0], method="GET", path="/", signal="/", now=entry[1]), requests))
    with monitor._connection() as db:
        windows = db.execute("SELECT COUNT(*) FROM anomaly_windows").fetchone()[0]
    anomaly_events = [event for event in monitor.events(100) if event["rule"] == "ml-anomaly"]
    assert windows <= 1
    assert len(anomaly_events) <= 1


def test_packet_analyzer_detects_syn_and_distributed_sources():
    from scapy.layers.inet import IP, TCP
    from scapy.layers.l2 import Ether

    from packet_monitor import PacketAnalyzer

    packets = []
    for number in range(4):
        packets.append(Ether() / IP(src=f"198.51.100.{number + 1}", dst="203.0.113.8") / TCP(dport=443, flags="S"))
    report = PacketAnalyzer(syn_packet_threshold=4, distributed_source_threshold=4).analyze(packets)
    kinds = {finding["type"] for finding in report["findings"]}
    assert report["packets_seen"] == 4
    assert {"high-syn-rate", "distributed-source-fan-in"} <= kinds
    assert all(finding["action"] == "alert-only" for finding in report["findings"])


def test_packet_analyzer_detects_udp_flood_indicator():
    from scapy.layers.inet import IP, UDP
    from scapy.layers.l2 import Ether

    from packet_monitor import PacketAnalyzer

    packets = [
        Ether() / IP(src=f"198.51.100.{number + 1}", dst="203.0.113.9") / UDP(dport=53)
        for number in range(3)
    ]
    report = PacketAnalyzer(udp_packet_threshold=3).analyze(packets)
    assert any(finding["type"] == "high-udp-rate" for finding in report["findings"])


def test_packet_analyzer_ignores_non_ip_packets():
    from scapy.layers.l2 import ARP, Ether

    from packet_monitor import PacketAnalyzer

    report = PacketAnalyzer().analyze([Ether() / ARP()])
    assert report["packets_seen"] == 0
    assert report["findings"] == []


def test_block_expires_and_allows_source_again(tmp_path):
    monitor = RequestMonitor(tmp_path / "expire.sqlite3", rate_limit=2, block_seconds=5)
    for timestamp in (100, 101, 102):
        decision = monitor.inspect(source_ip="198.51.100.30", method="GET", path="/", signal="/", now=timestamp)
    assert decision["action"] == "blocked"
    after_expiry = monitor.inspect(source_ip="198.51.100.30", method="GET", path="/", signal="/", now=113)
    assert after_expiry["action"] == "allowed"


@pytest.fixture
def client(tmp_path):
    sentinel.app.config.update(TESTING=True)
    sentinel.app.config["SECURITY_MONITOR"] = RequestMonitor(tmp_path / "security.sqlite3", rate_limit=3, block_seconds=30)
    sentinel.app.config["AUDIT_LEDGER"] = SQLiteAuditLedger(tmp_path / "audit.sqlite3")
    return sentinel.app.test_client()


def _create_client():
    sentinel.app.config.update(TESTING=True)
    return sentinel.app.test_client()
