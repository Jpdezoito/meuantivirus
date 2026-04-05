param(
    [string]$InstallDir = "$env:ProgramFiles\SentinelaPC",
    [string]$UserDataDir = "$env:LOCALAPPDATA\SentinelaPC",
    [switch]$Launch
)

$ErrorActionPreference = "Stop"

$checks = @(
    (Join-Path $InstallDir "SentinelaPC.exe"),
    (Join-Path $InstallDir "_internal\app\assets\branding\logo-app-256.png"),
    (Join-Path $UserDataDir "logs"),
    (Join-Path $UserDataDir "reports"),
    (Join-Path $UserDataDir "quarantine"),
    (Join-Path $UserDataDir "app\data")
)

$failed = $false
foreach ($path in $checks) {
    if (Test-Path $path) {
        Write-Host "[OK] $path"
    }
    else {
        Write-Host "[ERRO] Ausente: $path"
        $failed = $true
    }
}

if ($failed) {
    throw "Validacao falhou: ha caminhos obrigatorios ausentes."
}

if ($Launch) {
    Start-Process -FilePath (Join-Path $InstallDir "SentinelaPC.exe")
    Write-Host "Aplicativo iniciado para teste manual."
}

Write-Host "Validacao de instalacao concluida com sucesso."
