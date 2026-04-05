# Build and start the full stack (from repo root).
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Get the script directory and change to repo root
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$root = Split-Path -Parent $scriptDir
Set-Location $root

Write-Host "Working directory: $root" -ForegroundColor Cyan

# Check if Docker is running
docker info > $null 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Error "Docker is not running"
    exit 1
}

# Check if docker-compose.yml exists
$composeFile = Join-Path $root "docker-compose.yml"
if (-not (Test-Path $composeFile)) {
    Write-Error "docker-compose.yml not found at $composeFile"
    exit 1
}

Write-Host "Starting Docker Compose..." -ForegroundColor Green
docker compose up -d --build

Write-Host ""
Write-Host "Services started:" -ForegroundColor Green
Write-Host "  API: http://localhost:8000"
Write-Host "  Grafana: http://localhost:3000 (admin/admin)"
Write-Host "  Prometheus: http://localhost:9090"
Write-Host "  Alertmanager: http://localhost:9094"
Write-Host ""
Write-Host "To view logs: docker compose logs -f" -ForegroundColor Yellow
Write-Host "To stop: docker compose down" -ForegroundColor Yellow
