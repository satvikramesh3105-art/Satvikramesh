"""Create/verify/recover SQLite snapshots without replacing live databases."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sqlite3
import sys
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from audit_ledger import SQLiteAuditLedger


BACKUP_FORMAT = "sentinel-sqlite-backup-v1"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _sqlite_integrity(path: Path) -> bool:
    try:
        with closing(sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True)) as db:
            return db.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    except sqlite3.Error:
        return False


def _copy_sqlite(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(f"file:{source.resolve().as_posix()}?mode=ro", uri=True)) as src:
        with closing(sqlite3.connect(destination)) as dst:
            src.backup(dst)
            dst.commit()


def create_backup(sources: dict[str, Path], backup_root: Path) -> Path:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    snapshot = backup_root / f"sentinel-backup-{timestamp}"
    snapshot.mkdir(parents=True, exist_ok=False)
    manifest: dict[str, Any] = {"format": BACKUP_FORMAT, "created_at": datetime.now(timezone.utc).isoformat(), "databases": {}}
    try:
        for name, source in sources.items():
            if not source.is_file():
                continue
            if name not in {"security.sqlite3", "audit.sqlite3"}:
                raise ValueError(f"Unrecognized database name: {name}")
            target = snapshot / name
            _copy_sqlite(source, target)
            if not _sqlite_integrity(target):
                raise ValueError(f"SQLite integrity check failed: {target}")
            if name == "audit.sqlite3" and not SQLiteAuditLedger(target).verify():
                raise ValueError("Audit chain verification failed; refusing to create a backup from a modified ledger.")
            manifest["databases"][name] = {
                "sha256": _sha256(target),
                "bytes": target.stat().st_size,
                "sqlite_integrity": "ok",
            }
        if not manifest["databases"]:
            raise ValueError("No source database files were found.")
        manifest_path = snapshot / "manifest.json"
        manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
        return snapshot
    except Exception:
        shutil.rmtree(snapshot, ignore_errors=True)
        raise


def verify_backup(snapshot: Path) -> dict[str, Any]:
    manifest_path = snapshot / "manifest.json"
    if not manifest_path.is_file():
        raise ValueError("Backup manifest is missing.")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("format") != BACKUP_FORMAT or not isinstance(manifest.get("databases"), dict):
        raise ValueError("Unsupported backup manifest.")
    verified: list[str] = []
    for name, metadata in manifest["databases"].items():
        if name not in {"security.sqlite3", "audit.sqlite3"}:
            raise ValueError(f"Unexpected database name in manifest: {name}")
        database = snapshot / name
        if not database.is_file() or _sha256(database) != metadata.get("sha256"):
            raise ValueError(f"Backup checksum mismatch: {name}")
        if not _sqlite_integrity(database):
            raise ValueError(f"SQLite integrity check failed: {name}")
        if name == "audit.sqlite3" and not SQLiteAuditLedger(database).verify():
            raise ValueError("Backup audit hash chain is invalid.")
        verified.append(name)
    if not verified:
        raise ValueError("Backup contains no database snapshots.")
    return {"valid": True, "created_at": manifest.get("created_at"), "databases": verified}


def restore_to_directory(snapshot: Path, destination: Path) -> list[Path]:
    """Restore verified copies to a separate recovery directory, never in-place."""
    verification = verify_backup(snapshot)
    destination.mkdir(parents=True, exist_ok=True)
    restored: list[Path] = []
    for name in verification["databases"]:
        output = destination / name
        if output.exists():
            raise FileExistsError(f"Refusing to overwrite existing recovery file: {output}")
        _copy_sqlite(snapshot / name, output)
        restored.append(output)
    return restored


def main() -> int:
    parser = argparse.ArgumentParser(description="Snapshot/verify/restore Sentinel local SQLite metadata safely.")
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--create", action="store_true")
    action.add_argument("--verify", type=Path)
    action.add_argument("--restore", type=Path)
    parser.add_argument("--backup-root", type=Path, default=Path("backups"))
    parser.add_argument("--destination", type=Path, default=Path("recovery"))
    parser.add_argument("--security-db", type=Path, default=Path("instance/sentinel-security.sqlite3"))
    parser.add_argument("--audit-db", type=Path, default=Path("instance/audit.sqlite3"))
    args = parser.parse_args()
    try:
        if args.create:
            output = create_backup({"security.sqlite3": args.security_db, "audit.sqlite3": args.audit_db}, args.backup_root)
            print(f"Verified backup created: {output}")
        elif args.verify:
            print(json.dumps(verify_backup(args.verify), indent=2))
        else:
            restored = restore_to_directory(args.restore, args.destination)
            print("Recovered verified copies (live databases were not overwritten):")
            for path in restored:
                print(path)
    except (OSError, sqlite3.Error, ValueError, json.JSONDecodeError) as error:
        print(f"Backup operation failed: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
