param(
    [string]$PythonExe = ".\.venv\Scripts\python.exe",
    [string]$AppVersion = "0.1.0",
    [switch]$InstallBuildDeps,
    [switch]$Clean
)

$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Set-Location $repoRoot

if (-not (Test-Path $PythonExe)) {
    throw "Python nao encontrado em '$PythonExe'. Informe -PythonExe ou crie o venv."
}

if ($InstallBuildDeps) {
    & $PythonExe -m pip install --upgrade pip
    & $PythonExe -m pip install -r "installer\requirements-build.txt"
}

if ($Clean) {
    if (Test-Path "build") { Remove-Item -Recurse -Force "build" }
    if (Test-Path "dist\SentinelaPC") { Remove-Item -Recurse -Force "dist\SentinelaPC" }
}

$hiddenImports = @(
    "app.services.analyzer_behavior",
    "app.services.analyzer_browser",
    "app.services.analyzer_context",
    "app.services.analyzer_hash",
    "app.services.analyzer_static",
    "app.services.archive_inspector",
    "app.services.behavior_monitor",
    "app.services.edge_extension_service",
    "app.services.network_intrusion_monitor",
    "app.services.pre_execution_monitor",
    "app.services.ransomware_behavior_monitor",
    "app.services.reputation_service",
    "app.services.risk_engine",
    "app.services.script_pattern_analyzer",
    "app.services.shortcut_analyzer",
    "app.services.url_threat_service",
    "app.services.usb_guard_monitor",
    "app.services.virustotal_service",
    "app.integration.antivirus_bridge"
)

$pyInstallerArgs = @(
    "-m", "PyInstaller",
    "--noconfirm",
    "--clean",
    "--windowed",
    "--name", "SentinelaPC",
    "--icon", "app\assets\branding\logo-installer.ico",
    "--version-file", "installer\version-info.txt",
    "--paths", ".",
    "--add-data", "app;app",
    "--add-data", "installer;installer",
    "main.py"
)

foreach ($module in $hiddenImports) {
    $pyInstallerArgs += @("--hidden-import", $module)
}

& $PythonExe $pyInstallerArgs

$exePath = Join-Path $repoRoot "dist\SentinelaPC\SentinelaPC.exe"
if (-not (Test-Path $exePath)) {
    throw "Build falhou: executavel nao encontrado em '$exePath'."
}

$requiredPaths = @(
    "dist\SentinelaPC\_internal\app\assets\branding\logo-app-256.png",
    "dist\SentinelaPC\_internal\app\data",
    "dist\SentinelaPC\_internal\installer"
)

foreach ($path in $requiredPaths) {
    if (-not (Test-Path $path)) {
        throw "Build incompleto: item obrigatorio ausente '$path'."
    }
}

Write-Host "Build concluido com sucesso: $exePath"
