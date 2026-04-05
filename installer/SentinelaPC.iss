; Script de exemplo do Inno Setup para o SentinelaPC.
; Objetivos deste instalador:
; - instalar o executavel em local apropriado no Windows;
; - criar atalho no Menu Iniciar;
; - oferecer atalho opcional na Area de Trabalho;
; - criar as pastas gravaveis esperadas pela aplicacao;
; - manter uma base organizada para futuras atualizacoes.

#define MyAppName "SentinelaPC"
#define MyAppVersion "0.1.0"
#define MyAppPublisher "SentinelaPC"
#define MyAppExeName "SentinelaPC.exe"
#define MyAppDistDir "..\dist\SentinelaPC"
#define MyAppAppId "{{8B67F8FA-1A3E-4C8F-9E4E-9E5A2C5C61A1}"

[Setup]
; Identidade estavel do aplicativo.
; Mantenha o mesmo AppId nas proximas versoes para permitir upgrade/desinstalacao corretos.
AppId={#MyAppAppId}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher={#MyAppPublisher}

; Diretoria recomendada para executaveis instalados.
; Como os dados gravaveis vao para LOCALAPPDATA, o programa pode ficar em Program Files.
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}

; Pasta onde o instalador gerado sera salvo.
OutputDir=.
OutputBaseFilename=SentinelaPC-Setup-{#MyAppVersion}
Compression=lzma
SolidCompression=yes
WizardStyle=modern
SetupIconFile=..\app\assets\branding\logo-installer.ico

; Instalar em 64 bits quando o sistema suportar.
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible

; Opcional, mas util para futuras evolucoes do instalador.
PrivilegesRequired=admin
UninstallDisplayIcon={app}\{#MyAppExeName}

[Languages]
Name: "portuguesebrazil"; MessagesFile: "compiler:Languages\BrazilianPortuguese.isl"

[Tasks]
; Atalho opcional na area de trabalho.
Name: "desktopicon"; Description: "Criar atalho na Area de Trabalho"; GroupDescription: "Atalhos adicionais:"; Flags: unchecked

[Files]
; Copia todo o conteudo do build onedir do PyInstaller.
; O instalador pressupoe que o build ja foi gerado em dist\SentinelaPC.
Source: "{#MyAppDistDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Dirs]
; Pastas gravaveis por usuario.
; A aplicacao usa LOCALAPPDATA\SentinelaPC quando esta empacotada.
Name: "{localappdata}\{#MyAppName}"
Name: "{localappdata}\{#MyAppName}\logs"
Name: "{localappdata}\{#MyAppName}\quarantine"
Name: "{localappdata}\{#MyAppName}\reports"
Name: "{localappdata}\{#MyAppName}\app"
Name: "{localappdata}\{#MyAppName}\app\data"

[Icons]
; Atalho principal no Menu Iniciar.
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"

; Atalho para desinstalacao no grupo do Menu Iniciar.
Name: "{group}\Desinstalar {#MyAppName}"; Filename: "{uninstallexe}"

; Atalho opcional na Area de Trabalho.
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
; Opcao para abrir o programa ao final da instalacao.
Name: "{app}\{#MyAppExeName}"; Description: "Executar {#MyAppName}"; Flags: nowait postinstall skipifsilent
