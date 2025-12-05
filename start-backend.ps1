# Script para iniciar el backend en puerto 8000
Write-Host "Iniciando Backend (FastAPI) en puerto 8000..." -ForegroundColor Green
Set-Location "$PSScriptRoot\backend"

# Activar virtualenv
Write-Host "Activando entorno virtual..." -ForegroundColor Cyan
& ".\\.venv\Scripts\Activate.ps1"

# Verificar si existe .env, si no, crear uno
if (-not (Test-Path ".env")) {
    Write-Host "Archivo .env no encontrado. Por favor, configura tu MONGODB_URI en backend\.env" -ForegroundColor Yellow
}

# Instalar dependencias si no existen
Write-Host "Verificando dependencias..." -ForegroundColor Cyan
python -m pip install -r requirements.txt

# Iniciar servidor
Write-Host "Servidor iniciado en http://localhost:8000" -ForegroundColor Green
Write-Host "Documentación en http://localhost:8000/docs" -ForegroundColor Cyan
python -m uvicorn main:app --host 0.0.0.0 --port 8000 --reload
DH