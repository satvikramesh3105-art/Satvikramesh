from __future__ import annotations

import re
import uuid
from datetime import timedelta
from typing import Any

from minio import Minio
from minio.error import S3Error
from werkzeug.utils import secure_filename


_OBJECT_ID = re.compile(r"^[0-9a-f]{32}$")
_MAX_LISTED_OBJECTS = 10_000
_DISPLAY_OBJECTS = 100


class LocalObjectVault:
    """Issue short-lived browser URLs for encrypted objects in a private MinIO bucket."""

    def __init__(
        self,
        *,
        internal_endpoint: str,
        public_endpoint: str,
        access_key: str,
        secret_key: str,
        bucket: str = "sentinel-vault",
    ) -> None:
        if not all((internal_endpoint, public_endpoint, access_key, secret_key, bucket)):
            raise ValueError("MinIO endpoints, credentials, and bucket must be configured.")
        self.bucket = bucket
        self.internal = Minio(
            internal_endpoint,
            access_key=access_key,
            secret_key=secret_key,
            region="us-east-1",
            secure=False,
        )
        self.public = Minio(
            public_endpoint,
            access_key=access_key,
            secret_key=secret_key,
            region="us-east-1",
            secure=False,
        )

    def _ensure_bucket(self) -> None:
        if not self.internal.bucket_exists(self.bucket):
            self.internal.make_bucket(self.bucket)

    @staticmethod
    def _object_name(name: str) -> str:
        safe_name = secure_filename(name)
        if not safe_name or len(safe_name) > 180 or not safe_name.lower().endswith(".sentinel"):
            raise ValueError("name must be a filename ending in .sentinel (maximum 180 characters).")
        return safe_name

    def create_upload_urls(self, name: str) -> dict[str, str]:
        safe_name = self._object_name(name)
        self._ensure_bucket()
        object_id = uuid.uuid4().hex
        object_key = f"{object_id}/{safe_name}"
        manifest_key = f"{object_key}.manifest.json"
        expiry = timedelta(minutes=5)
        return {
            "object_id": object_id,
            "name": safe_name,
            "file_url": self.public.presigned_put_object(self.bucket, object_key, expires=expiry),
            "manifest_url": self.public.presigned_put_object(self.bucket, manifest_key, expires=expiry),
        }

    def list_objects(self) -> list[dict[str, Any]]:
        self._ensure_bucket()
        entries: dict[str, dict[str, Any]] = {}
        scanned = 0
        for item in self.internal.list_objects(self.bucket, recursive=True):
            scanned += 1
            if scanned > _MAX_LISTED_OBJECTS:
                raise RuntimeError("Vault listing exceeded 10,000 objects; archive older objects before continuing.")
            parts = item.object_name.split("/", 1)
            if len(parts) != 2 or not _OBJECT_ID.fullmatch(parts[0]):
                continue
            object_id, name = parts
            if name.endswith(".manifest.json"):
                continue
            if not name.lower().endswith(".sentinel"):
                continue
            entries[object_id] = {
                "id": object_id,
                "name": name,
                "size": int(item.size),
                "last_modified": item.last_modified.isoformat() if item.last_modified else None,
                "has_manifest": False,
                "_key": item.object_name,
            }
        for entry in entries.values():
            try:
                self.internal.stat_object(self.bucket, f"{entry['_key']}.manifest.json")
                entry["has_manifest"] = True
            except S3Error as error:
                if error.code not in {"NoSuchKey", "NoSuchObject", "NotFound"}:
                    raise
            del entry["_key"]
        return sorted(
            entries.values(),
            key=lambda entry: entry["last_modified"] or "",
            reverse=True,
        )[:_DISPLAY_OBJECTS]

    def create_download_urls(self, object_id: str) -> dict[str, Any] | None:
        if not _OBJECT_ID.fullmatch(object_id):
            return None
        for entry in self.list_objects():
            if entry["id"] != object_id:
                continue
            self._ensure_bucket()
            object_key = f"{object_id}/{entry['name']}"
            expiry = timedelta(minutes=5)
            return {
                "name": entry["name"],
                "file_url": self.public.presigned_get_object(self.bucket, object_key, expires=expiry),
                "manifest_url": (
                    self.public.presigned_get_object(
                        self.bucket,
                        f"{object_key}.manifest.json",
                        expires=expiry,
                    )
                    if entry["has_manifest"]
                    else None
                ),
            }
        return None
