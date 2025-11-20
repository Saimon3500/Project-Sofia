# Script para iniciar Backend y Frontend juntos
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Iniciando Sofia App (Backend + Frontend)" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$backendPath = "$PSScriptRoot\backend"
$frontendPath = "$PSScriptRoot\sofia-app"

# Verificar .env
if (-not (Test-Path "$backendPath\.env")) {
    Write-Host "⚠️  ADVERTENCIA: Archivo backend\.env no encontrado" -ForegroundColor Yellow
    Write-Host "Por favor, configura las siguientes variables en backend\.env:" -ForegroundColor Yellow
    Write-Host "  - MONGODB_URI" -ForegroundColor Yellow
    Write-Host "  - JWT_SECRET" -ForegroundColor Yellow
    Write-Host ""
}

# Iniciar Backend en nueva ventana
Write-Host "Iniciando Backend en puerto 8000..." -ForegroundColor Green
$backendScript = "$PSScriptRoot\start-backend.ps1"
Start-Process powershell -ArgumentList "-NoExit", "-ExecutionPolicy", "Bypass", "-File", $backendScript

# Esperar a que el backend inicie
Write-Host "Esperando a que el backend inicie..." -ForegroundColor Yellow
Start-Sleep -Seconds 3

# Iniciar Frontend en nueva ventana
Write-Host "Iniciando Frontend en puerto 8081..." -ForegroundColor Green
$frontendScript = "$PSScriptRoot\start-frontend.ps1"
Start-Process powershell -ArgumentList "-NoExit", "-ExecutionPolicy", "Bypass", "-File", $frontendScript

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "✅ Ambos servidores se están iniciando..." -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Backend API:  http://localhost:8000" -ForegroundColor Cyan
Write-Host "Backend Docs: http://localhost:8000/docs" -ForegroundColor Cyan
Write-Host "Frontend:     http://localhost:8081" -ForegroundColor Cyan
Write-Host ""
Write-Host "Presiona Ctrl+C en cada ventana para detener los servidores" -ForegroundColor Yellow
