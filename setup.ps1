$ErrorActionPreference = "Stop"

$envPath = Join-Path $PSScriptRoot ".env"
if (Test-Path $envPath) {
    throw ".env already exists. Keep its credentials, or remove that specific file before generating new ones."
}

function New-RandomCredential([int]$ByteCount) {
    $bytes = [byte[]]::new($ByteCount)
    $generator = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $generator.GetBytes($bytes)
    }
    finally {
        $generator.Dispose()
    }
    return [Convert]::ToBase64String($bytes).TrimEnd("=").Replace("+", "A").Replace("/", "B")
}

$username = "sentinel" + (New-RandomCredential 12)
$password = New-RandomCredential 36
$content = "MINIO_ROOT_USER=$username`r`nMINIO_ROOT_PASSWORD=$password`r`n"
Set-Content -Path $envPath -Value $content -Encoding Ascii -NoNewline
Write-Output "Created local MinIO credentials in .env. Keep this file private and do not share it."
