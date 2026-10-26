$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

if (-not (Test-Path ".env")) {
    throw "Run .\setup.ps1 first to create local MinIO credentials."
}

docker compose build sentinel
if ($LASTEXITCODE -ne 0) { throw "Could not build the Sentinel image." }
docker compose pull edge minio
if ($LASTEXITCODE -ne 0) { throw "Could not download the pinned edge and MinIO images." }
docker save --output sentinel-images.tar sentinel-app:local nginx:1.27.5-alpine minio/minio:RELEASE.2025-07-23T15-54-02Z
if ($LASTEXITCODE -ne 0) { throw "Could not export the Docker images." }
Write-Output "Created sentinel-images.tar. Transfer it and the project folder to the offline target; generate a fresh .env on that target."
