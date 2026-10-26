from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

import object_vault
from object_vault import LocalObjectVault


class FakeMinio:
    def __init__(self, *_args, **_kwargs):
        self.created_buckets = []

    def bucket_exists(self, _bucket):
        return False

    def make_bucket(self, bucket):
        self.created_buckets.append(bucket)

    def presigned_put_object(self, bucket, key, expires):
        assert expires.total_seconds() == 300
        return f"http://localhost:8080/{bucket}/{key}?signed=put"

    def presigned_get_object(self, bucket, key, expires):
        assert expires.total_seconds() == 300
        return f"http://localhost:8080/{bucket}/{key}?signed=get"

    def list_objects(self, _bucket, recursive):
        assert recursive is True
        now = datetime.now(timezone.utc)
        return iter([
            SimpleNamespace(object_name=f"{'a' * 32}/report.sentinel", size=123, last_modified=now),
            SimpleNamespace(object_name=f"{'a' * 32}/report.sentinel.manifest.json", size=256, last_modified=now),
            SimpleNamespace(object_name="unmanaged/readme.txt", size=5, last_modified=now),
        ])

    def stat_object(self, _bucket, key):
        assert key == f"{'a' * 32}/report.sentinel.manifest.json"


@pytest.fixture
def vault(monkeypatch):
    monkeypatch.setattr(object_vault, "Minio", FakeMinio)
    return LocalObjectVault(
        internal_endpoint="minio:9000",
        public_endpoint="localhost:8080",
        access_key="test-user",
        secret_key="test-secret",
    )


def test_upload_urls_target_only_encrypted_artifacts(vault):
    upload = vault.create_upload_urls("report.txt.sentinel")
    assert len(upload["object_id"]) == 32
    assert upload["name"] == "report.txt.sentinel"
    assert "/sentinel-vault/" in upload["file_url"]
    assert upload["manifest_url"].endswith(".manifest.json?signed=put")
    with pytest.raises(ValueError, match="ending in .sentinel"):
        vault.create_upload_urls("plaintext.txt")


def test_vault_listing_only_exposes_managed_ciphertext_and_manifest_state(vault):
    objects = vault.list_objects()
    assert objects == [{
        "id": "a" * 32,
        "name": "report.sentinel",
        "size": 123,
        "last_modified": objects[0]["last_modified"],
        "has_manifest": True,
    }]


def test_download_urls_are_only_created_for_listed_objects(vault):
    urls = vault.create_download_urls("a" * 32)
    assert urls["name"] == "report.sentinel"
    assert urls["file_url"].endswith("report.sentinel?signed=get")
    assert urls["manifest_url"].endswith("report.sentinel.manifest.json?signed=get")
    assert vault.create_download_urls("../secret") is None
