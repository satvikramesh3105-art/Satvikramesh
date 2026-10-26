# Sentinel project handoff

Upload this file, the project source, and the relevant phase presentations to Claude. Ask Claude to inspect the actual current files before changing anything, then continue implementation and testing from this checkpoint.

## Project and goal

- Project: Sentinel, a defensive security and secure-file-storage prototype.
- Current project folder: `SENT`.
- Reference presentations in the parent folder include `PHASE-0.pptx`, `PHASE-1.pptx`, and `PHASE-2.1.pptx`. Upload the decks as well as this handoff so Claude can verify the requirements directly.
- The goal is to finish the demonstrated Phase 0/1/2 scope as far as is technically responsible, then deploy the project to another Windows system and verify it works.
- User-selected deployment: Windows + Docker Desktop/Compose; local MinIO object storage; localhost-only access; no public or LAN exposure; no internet needed at runtime after images/dependencies have been acquired.
- User-selected audit: retain the local SQLite hash-linked audit ledger. This explicitly does **not** satisfy the PPT's blockchain/decentralized-ledger requirement.

## Current implementation

The project already includes:

- Flask dashboard, HTTP request monitoring, signature alerts, rate limiting and temporary source-IP blocks.
- Optional Isolation Forest anomaly scoring. It is heuristic/advisory; the included demo model is synthetic and does not automatically block anomalies.
- Browser-only AES-GCM file encryption/decryption and Merkle manifests; file bytes and passphrases must not be sent to Flask.
- Manual integrity verification and user-triggered verification/download of a separate trusted backup.
- SQLite security events and a hash-linked audit ledger. The ledger is local, can be rewritten by a privileged host operator, and is not a blockchain.
- Nginx reverse proxy and Docker Compose configuration.
- Separate passive Scapy PCAP/interface analysis. It is alert-only, not integrated packet filtering or blocking.
- Local metadata snapshots in the Compose backup service.

The current working tree has also been extended with:

- `object_vault.py`: MinIO integration for listing encrypted files and issuing short-lived signed upload/download URLs.
- `app.py`: `/api/vault` status, listing, upload-URL and download-URL endpoints.
- `templates/index.html`, `static/app.js`, `static/vault.css`: browser vault UI. It uploads only the encrypted `.sentinel` artifact and manifest directly through Nginx to MinIO.
- `docker-compose.yml`: MinIO service with a named persistent volume, not published to the host.
- `nginx.conf`: direct `/sentinel-vault/` proxy route so encrypted uploads bypass Flask.
- `setup.ps1`: creates local random MinIO credentials in `.env`.
- `Export-OfflineBundle.ps1`: builds/collects Docker images into `sentinel-images.tar` for transfer to an offline Windows host.
- `tests/test_object_vault.py` and additions to `tests/test_app.py`.
- Updated deployment instructions in `README.md`; `sentinel-images.tar` is ignored by `.gitignore`.

### Important current-mode distinction

The Flask app that was last launched directly with the project's `.venv` is at `http://127.0.0.1:5000`. It has **no MinIO configuration**, so `/api/vault/objects` returns HTTP 503 and the new local vault UI reports that the vault is not configured. This is expected in direct-Python mode. The MinIO feature is intended to run with Docker Compose at `http://localhost:8080`.

## Last verification checkpoint

- `python -m pytest -q`: **40 passed** after the MinIO/vault changes.
- Modified Python files passed `compileall`.
- Windows deployment scripts parsed successfully in PowerShell.
- MinIO SDK generated a signed URL with host `localhost:8080` and a 300-second expiry.
- The direct Flask dashboard returned HTTP 200 and served the updated `app.js`.
- **Docker was not installed/available in the development environment**, so Compose parsing by Docker, image builds, container health, MinIO bucket initialization, browser upload/download against MinIO, and offline image-bundle deployment have **not** been end-to-end tested.
- No claim has been made that the prototype is production-ready or meets an availability SLA.

## Work still needed

### 1. Complete and validate the Compose/MinIO vault first

1. Inspect the current changes and Compose/Nginx/MinIO interactions. Do not assume the service is correct merely because unit tests pass.
2. On a machine with Docker Desktop, run Compose config validation and build/start the stack. Resolve startup/healthcheck or bucket/signature errors.
3. End-to-end test in a browser: encrypt a harmless test file, upload ciphertext and manifest, verify Flask did not receive file bytes, list and download both objects, then decrypt and verify integrity locally.
4. Check failure cases: MinIO unavailable, expired signed URL, failed manifest upload, missing object/manifest, invalid filename, and restart persistence.
5. Confirm the 100 MiB Nginx ciphertext limit matches the UI's actual intended file-size limit. The current UI text recommends files up to 50 MiB, but encryption overhead and the manifest should be considered.
6. Confirm object-list bounds, cleanup/retention, backup and restore, and offline export/import scripts on the actual target OS. Do not transfer `.env`; generate fresh target-local credentials.

### 2. Layer 4 protection and mitigation

The PPT describes real-time Layer 4 packet inspection and mitigation. The existing packet monitor is a separate passive analyzer and **must stay clearly labeled alert-only unless a separately designed, authorized mitigation backend is implemented and tested**.

Before implementing blocking, have the owner confirm the exact intended authorized lab environment and host OS/network boundary. Do not silently add host firewall rules, change system firewall state, or enable blocking against arbitrary interfaces. Prefer an explicitly opt-in, narrowly scoped mitigation adapter with:

- default monitor/alert-only mode;
- explicit allow-listed lab interfaces/targets and safe thresholds;
- dry-run/preview, audit events, expiry/automatic rollback, and an emergency disable path;
- platform-specific behavior isolated behind an interface;
- tests using synthetic packet inputs and mocked mitigation actions;
- documentation that this is not general-purpose DDoS protection.

Evaluate whether the actual PPT requirement can responsibly be demonstrated with Nginx/HTTP rate limits plus packet alerts, rather than claiming volumetric Layer 4 blocking.

### 3. Integrity auditing and recovery

- Current Merkle validation and recovery are user-triggered and browser-local. There is no scheduled cloud/object rescan, alert pipeline, or automatic recovery.
- Design any periodic integrity check to compare stored encrypted-object bytes against a separately trusted manifest/root. Decide how the trusted root is protected from an attacker who can replace both object and manifest.
- If adding a background worker, add persistent job state, failure reporting, retry/backoff, concurrency limits, and tests. Never overwrite an original object during recovery.
- Keep encryption/decryption entirely in the browser; never stream plaintext or passphrases through Flask, Nginx, or MinIO.

### 4. Audit ledger and PPT claims

- SQLite was the user's chosen ledger. Keep describing it as a persistent local hash-linked audit database, **not independently immutable and not a blockchain**.
- Ask before changing the selection to a private Ethereum-compatible chain. A chain would add node infrastructure, persistent volumes, startup/health checks, transaction/key management, offline image transfer, failure handling, and end-to-end tests.
- Do not claim blockchain compliance, decentralized immutability, or tamper-proof logging from the existing SQLite database.

### 5. Deployment to a different Windows system

The intended flow is documented in `README.md`:

1. Ensure Docker Desktop and Compose are installed.
2. Generate credentials on the target using `.\setup.ps1`.
3. On a connected target: `docker compose up --build -d`.
4. On an offline target: build/export pinned images using `.\Export-OfflineBundle.ps1` on a connected machine; transfer project source and `sentinel-images.tar` through approved media, excluding `.env` and `.venv`; load images using `docker load -i sentinel-images.tar`; generate new credentials on target; start with `docker compose up -d --no-build --pull never`.
5. Confirm `http://localhost:8080`, health checks, vault upload/download, and named-volume persistence.

Test this sequence on a clean Windows machine or VM. Record exact Docker Desktop version, disk/image requirements, failures, and recovery procedure. Do not publish MinIO or the app to LAN/public interfaces: current setup has no login and no TLS for remote clients. Localhost HTTP is intentionally used for the selected same-machine deployment and browser Web Crypto secure-context behavior.

## Non-negotiable project constraints

- File encryption and decryption stay entirely in the browser using Web Crypto. Flask must never receive file bytes or passphrases.
- Clearly label the rate-limit visualizer as a simulation, packet capture as alert-only, and SQLite audit database as not independently immutable/not a blockchain.
- Do not add secrets, authentication claims, or production-readiness claims.
- Keep Docker Compose portability, Nginx edge limits, named-volume metadata persistence, automatic local snapshots, and Windows local-run/deployment steps.
- Add or update tests for backend behavior. Prefer scoped tests and run them after each change.
- Do not enable or describe destructive/real-world packet blocking without explicit scope, safeguards, owner authorization, and validation.

## Suggested first prompt to Claude

> Read `CLAUDE_HANDOFF.md`, the supplied Phase 0/1/2 PPTs, and the current repository. First inspect the working tree and verify the current tests. Continue the implementation in small, tested steps. Start by validating the Compose + MinIO encrypted-vault end to end on Docker if available; do not claim it works until you test it. Then propose a safe, explicitly scoped approach for the remaining Layer 4 requirement before implementing any packet blocking. Keep browser-only encryption, the selected SQLite ledger, the Windows/offline deployment target, and all project constraints in this handoff. Report each PPT requirement as implemented, partial, not implemented, or not safely verifiable, with evidence and remaining steps.
