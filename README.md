# Sentinel — Phase-aligned defensive prototype

Sentinel implements a demonstrable subset of the Phase 0/1/2 proposal: HTTP-layer attack-pattern and rate detection, temporary source-IP blocking, client-side file encryption, Merkle-root integrity manifests, and security event reporting. It is a defensive student prototype, not a universal IDS or production cloud-security service.

## Phase requirements mapped to implementation

| Deck requirement | Current implementation | Boundary |
|---|---|---|
| Adaptive DDoS shield / reverse-proxy interception | Docker Compose places Nginx in front of Flask. Nginx applies per-source request-rate and concurrent-connection limits; Flask applies configurable per-source request-rate limits and temporary blocks. An optional separate Scapy utility passively summarizes SYN/UDP/fan-in signals from a PCAP or a permitted local capture interface. | This is not inline packet blocking, SYN-cookie handling, packet-rate scrubbing, or protection against a distributed botnet. Run packet capture only on interfaces/network segments you own or are authorized to monitor. Nginx limit responses are visible in its container logs. In direct Windows development mode Nginx is not enabled. |
| Layer-7 traffic analysis | Flask inspects HTTP paths, query strings, selected headers, and JSON/form fields for a small, explicit set of SQLi, XSS, traversal, command-injection, and scanner patterns. Alerts and block metadata persist in SQLite. Optional Isolation Forest scoring analyzes aggregate request windows after the operator trains a model from a reviewed benign CSV baseline. | Signatures and unsupervised anomaly scores are heuristic; they can have false positives/negatives and do not identify attack intent. No labeled attack dataset was supplied; zero-day detection is not guaranteed. A synthetic demo model can be trained locally for illustration only. |
| Client-side AES-256-GCM privacy | Web Crypto encrypts and decrypts file bytes in the browser; the AES-GCM authentication tag covers both file content and serialized metadata; Flask receives neither file bytes nor passphrases. Compose includes a local MinIO vault; browsers send ciphertext and its manifest through Nginx to MinIO using short-lived signed URLs. | The local vault is single-machine and has no user accounts or per-file authorization. It is not managed cloud storage or a backup service. |
| Merkle multi-branch integrity | The browser builds a SHA-256, four-way Merkle tree over 1 MiB chunks and downloads a JSON manifest. Later verification recomputes every leaf and the root locally. | Keep the manifest separately in a trusted location. If an attacker can replace both the file and its manifest, an unsigned manifest alone cannot prove which version is authentic. |
| Security-event logging | Detection events persist in one SQLite database; the user-action audit chain uses a separate SQLite database with sequence numbers, previous hashes, and a verification endpoint. | The chain detects ordinary record edits/deletions/reordering but is still local and privileged-rewriteable. It is not a blockchain or decentralized ledger until roots are independently anchored. |
| Continuous audit / recovery | A user can reselect a file and saved manifest to verify for changes. If current data mismatches, the browser can verify a separate backup against the same trusted manifest and download a recovered copy. AES-GCM rejects modified ciphertext during decryption. SQLite WAL is backed by Docker volume storage. | No background cloud rescanning exists. Recovery is user-triggered and produces a separate download; it never overwrites the original. The app cannot recover if no independently retained matching backup and manifest exist. |
| Availability target / “detect any attack” | Request guardrails can reject some observed traffic. | No 99.9% availability measurement/SLA and no detector can guarantee recognition of every attack. |

An Isolation Forest demo baseline is optionally trained from synthetic data and stored under `instance/` for preview. The UI identifies its source as `synthetic-demo`; it is not a validated model of real traffic. Replace it with a reviewed benign baseline before interpreting any outlier alerts.

The no-plaintext-upload behavior is intentional: encryption and decryption stay in the browser. In Compose, the optional local MinIO vault accepts ciphertext and its Merkle manifest directly from the browser through the Nginx edge; Flask issues short-lived upload/download URLs but never receives file bytes, passphrases, or signed URLs. The vault is local-only and has no user accounts or per-file authorization. Keep it bound to localhost and do not expose it to a network. MinIO credentials are generated locally into an ignored `.env` file and should not be shared. Direct uploads to a separate provider-issued URL remain optional.

Request-rate metadata older than one day and security alerts older than 90 days are pruned during normal app traffic. Alert records contain the peer IP, HTTP method, matched route template (unmatched paths are redacted), rule, and action; query strings and inspected request payloads are not stored. Model scores are advisory aggregate-window alerts and never automatically block traffic. A model file is a trusted executable serialization: protect write access to the model directory and load only models you created.

The Compose backup worker snapshots the security and audit SQLite databases daily and keeps 14 days inside the same Docker volume. It waits for healthy application storage, reports snapshot failures in its logs, and retries after one hour; inspect `docker compose logs backup` to confirm backups are succeeding. Copy backups to a separate, access-controlled system for disaster recovery; a volume-local snapshot alone does not survive loss of its host/volume. The hash-linked ledger is a separate local database, not an independent immutable service. Use **Export head checkpoint** in the dashboard (or `/api/audit/checkpoint`) and retain the returned head hash outside this host if you need to compare later. Browser-owned files are never on the server and must be backed up by their owner together with the trusted manifest.

## Run locally on Windows

1. Install Python 3.10 or newer.
2. In this folder, create/activate a virtual environment: PowerShell `py -m venv .venv` then `.venv\Scripts\Activate.ps1`; Command Prompt `py -m venv .venv` then `.venv\Scripts\activate.bat`.
3. Install dependencies with `python -m pip install -r requirements.txt`.
4. Start the development server with `python app.py` and open `http://localhost:5000`.

This direct local mode exercises Flask's live HTTP checks, but it does not put Nginx in front of the app.

## Deploy on another system with Docker Compose

1. Install Docker Desktop and the Compose plugin on the Windows target, then copy the project folder there. The app and MinIO run locally; after images are available, normal use does not require internet access.
2. In PowerShell, run `.\setup.ps1` once. It generates random local MinIO credentials in `.env`; keep that file private and do not commit or share it.
3. For a target that can download images, run `docker compose up --build -d`. Wait for healthy services, then open `http://localhost:8080`. Nginx is the only published service and binds to localhost. Flask and MinIO are private to the Compose network; MinIO data and Sentinel metadata use separate named volumes.
4. To transfer the deployment to a machine that will be offline, first run `.\setup.ps1` and `.\Export-OfflineBundle.ps1` on an internet-connected Windows machine with Docker. Transfer the source files and `sentinel-images.tar` using approved media, but **exclude `.env` and `.venv`**. On the offline target, install Docker Desktop, run `docker load -i sentinel-images.tar`, run `.\setup.ps1` to generate new target-local credentials, and start with `docker compose up -d --no-build --pull never`. Docker image transfer and disk space are required; this process does not download anything at runtime.
5. Encrypt a test file in the browser and use **Upload encrypted file & manifest**. The upload bytes go through Nginx directly to MinIO; they are not sent to Flask. The vault lets you list and download stored ciphertext and manifests. MinIO keeps these objects in the `sentinel_vault` volume.
6. Review logs with `docker compose logs edge sentinel minio backup`. Stop with `docker compose down`; do not add `-v` unless you intentionally want to delete persistent metadata and encrypted objects.

The default stack uses localhost HTTP, which is a secure browser context for Web Crypto. It is intentionally not reachable from other devices and has no login. Do not change the port binding or expose MinIO without first adding authentication, HTTPS, and access-control review. This portable local vault does not provide public cloud availability, automatic remote replication, or disaster recovery if the host/volume is lost.

## Safe verification and tests

- Install test/sensor extras with `python -m pip install -r requirements-dev.txt`, then run `python -m pytest`. The suite uses Flask's in-process test client and synthetic benign/attack-pattern/packet inputs; it does not generate a network flood.
- On the dashboard, select a non-sensitive test file, encrypt it, and keep the `.sentinel` ciphertext, `.manifest.json` Merkle manifest, and a separate trusted copy of the ciphertext. Select the ciphertext and manifest to verify integrity. Altering the current ciphertext should make AES-GCM decryption fail and Merkle verification report a mismatch; select the clean backup and choose **Verify & download backup** to receive a separate recovery download only if it matches that same trusted manifest.
- To demonstrate the live shield safely, review the automated request-signature and rate-limit tests. Do not run a flood or test against systems you do not own or have written permission to assess.

## Verify and recover local metadata

Create a one-time local snapshot with `python data_backup.py --create --security-db instance/sentinel-security.sqlite3`; verify one with `python data_backup.py --verify backups/<snapshot-folder>`; recover verified copies to a separate folder with `python data_backup.py --restore backups/<snapshot-folder> --destination recovery/<case-folder>`. The restore command intentionally never overwrites live databases. Stop the app and have an administrator inspect and replace data only after checking the verified recovery copies. These procedures restore local monitor/audit metadata, not browser-side file contents.

## Optional packet/transport analysis (passive only)

Install optional Scapy support with `python -m pip install -r requirements-packet-sensor.txt`. Analyze an existing authorized capture with `python packet_monitor.py --pcap path/to/authorized-capture.pcap`. On a permitted interface, `python packet_monitor.py --interface "Ethernet" --seconds 30` passively captures up to 30 seconds or 100,000 packets; Windows live capture may require Npcap and administrator rights. The output highlights configured SYN/UDP volume and source fan-in windows. It never transmits or blocks packets. This utility is separate from the Compose reverse proxy and does not automatically feed alerts into the web dashboard.

## Optional ML anomaly baseline

The model uses Isolation Forest over six aggregate HTTP window features. The checked-in project does not include a trained artifact. To create a demonstrative synthetic model, install the base requirements and run `python anomaly_model.py --demo`. For operational experiments, provide a reviewed CSV with at least 100 known-benign time windows and these columns: `requests,unique_sources,unique_routes,blocked_ratio,suspicious_events,source_entropy`. Train with `python anomaly_model.py --baseline benign-windows.csv --output instance/anomaly-model.joblib`, then restart the local app. In Compose, first start the services, copy the trusted model with `docker compose cp instance/anomaly-model.joblib sentinel:/data/anomaly-model.joblib`, then run `docker compose restart sentinel`. The ML signal is an advisory outlier, not a trained attack classifier; tune the baseline and expected contamination and review alerts before claiming useful recall/precision.

## Tuning

Set `SENTINEL_RATE_LIMIT` (default 60), `SENTINEL_RATE_WINDOW` (default 10 seconds), and `SENTINEL_BLOCK_SECONDS` (default 60) for Flask's per-source HTTP guard. Do not trust client-supplied `X-Forwarded-For`; Compose enables exactly one trusted proxy hop and Nginx overwrites that header before proxying. Verify Nginx image/configuration, rate limits, volumes, and TLS termination on the target host before deployment.

## Current readiness and unverified infrastructure

The HTTP monitor, model scoring path, local backup tool, audit verification, Merkle browser workflow, and packet-summary analyzer have automated tests. The Compose deployment is not certified against production load or adversarial traffic. Docker/Nginx were not available for an end-to-end container test on the development machine, and live network capture is dependent on host capture drivers/permissions. Do not claim packet-level flood blocking, botnet protection, production readiness, or an availability SLA based on these tests.
