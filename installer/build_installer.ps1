param(
    [string]$IsccPath = "C:\Program Files (x86)\Inno Setup 6\ISCC.exe",
    [string]$AppVersion = "0.1.0"
)

$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Set-Location $repoRoot

$issPath = Join-Path $repoRoot "installer\SentinelaPC.iss"
$distExe = Join-Path $repoRoot "dist\SentinelaPC\SentinelaPC.exe"

if (-not (Test-Path $issPath)) {
    throw "Script do Inno Setup nao encontrado em '$issPath'."
}

if (-not (Test-Path $distExe)) {
    throw "Executavel nao encontrado em '$distExe'. Rode primeiro installer\build_exe.ps1."
}

if (-not (Test-Path $IsccPath)) {
    throw "ISCC.exe nao encontrado em '$IsccPath'. Instale o Inno Setup 6 ou informe -IsccPath."
}

$arguments = @(
    "/DMyAppVersion=$AppVersion",
    "/DMyAppDistDir=..\dist\SentinelaPC",
    $issPath
)

& $IsccPath $arguments

$installerDir = Join-Path $repoRoot "dist\installer"
if (-not (Test-Path $installerDir)) {
    throw "Falha ao gerar instalador: pasta '$installerDir' nao foi criada."
}

$generated = Get-ChildItem -Path $installerDir -Filter "SentinelaPC-Setup-*.exe" | Sort-Object LastWriteTime -Descending | Select-Object -First 1
if (-not $generated) {
    throw "Falha ao gerar instalador: nenhum .exe encontrado em '$installerDir'."
}

Write-Host "Instalador gerado com sucesso: $($generated.FullName)"
