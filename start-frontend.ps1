# Script para iniciar el frontend en puerto 8081
Write-Host "Iniciando Frontend (Expo) en puerto 8081..." -ForegroundColor Green
Set-Location "$PSScriptRoot\sofia-app"

# Instalar dependencias si no existen
Write-Host "Verificando dependencias..." -ForegroundColor Cyan
npm install

# Iniciar servidor
Write-Host "Servidor iniciado en http://localhost:8081" -ForegroundColor Green
Write-Host "Accede a tu aplicación desde el navegador" -ForegroundColor Cyan
npx expo start --web --port 8081
