; Script profissional do Inno Setup para o SentinelaPC.
; Objetivos:
; - instalar o executavel em Program Files;
; - criar atalhos no Menu Iniciar e opcionalmente na Area de Trabalho;
; - preparar pastas gravaveis em LOCALAPPDATA;
; - registrar desinstalacao com opcao de limpar dados do usuario.

#ifndef MyAppName
	#define MyAppName "SentinelaPC"
#endif
#ifndef MyAppVersion
	#define MyAppVersion "0.1.0"
#endif
#ifndef MyAppPublisher
	#define MyAppPublisher "SentinelaPC"
#endif
#ifndef MyAppExeName
	#define MyAppExeName "SentinelaPC.exe"
#endif
#ifndef MyAppDistDir
	#define MyAppDistDir "..\dist\SentinelaPC"
#endif
#ifndef MyAppAppId
	#define MyAppAppId "{{8B67F8FA-1A3E-4C8F-9E4E-9E5A2C5C61A1}"
#endif

#define MyAppDataDir "{localappdata}\" + MyAppName

#ifnexist "{#MyAppDistDir}\{#MyAppExeName}"
	#error "Build nao encontrado. Gere o executavel antes: dist\\SentinelaPC\\SentinelaPC.exe"
#endif

[Setup]
AppId={#MyAppAppId}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher={#MyAppPublisher}
VersionInfoVersion={#MyAppVersion}
VersionInfoProductName={#MyAppName}
VersionInfoDescription=Instalador do {#MyAppName}
VersionInfoCompany={#MyAppPublisher}
VersionInfoCopyright=Copyright (c) {#MyAppPublisher}

DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
UsePreviousAppDir=yes
UsePreviousGroup=yes

OutputDir=..\dist\installer
OutputBaseFilename=SentinelaPC-Setup-{#MyAppVersion}
Compression=lzma
SolidCompression=yes
WizardStyle=modern
SetupIconFile=..\app\assets\branding\logo-installer.ico
UninstallDisplayName={#MyAppName}
SetupLogging=yes

ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible

PrivilegesRequired=admin
PrivilegesRequiredOverridesAllowed=dialog
UninstallDisplayIcon={app}\{#MyAppExeName}
ChangesAssociations=no

[Languages]
Name: "portuguesebrazil"; MessagesFile: "compiler:Languages\BrazilianPortuguese.isl"

[Tasks]
Name: "desktopicon"; Description: "Criar atalho na Area de Trabalho"; GroupDescription: "Atalhos adicionais:"; Flags: unchecked

[Files]
Source: "{#MyAppDistDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Dirs]
Name: "{localappdata}\{#MyAppName}"
Name: "{localappdata}\{#MyAppName}\logs"
Name: "{localappdata}\{#MyAppName}\quarantine"
Name: "{localappdata}\{#MyAppName}\reports"
Name: "{localappdata}\{#MyAppName}\app"
Name: "{localappdata}\{#MyAppName}\app\data"
Name: "{localappdata}\{#MyAppName}\config"

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"

Name: "{group}\Desinstalar {#MyAppName}"; Filename: "{uninstallexe}"

Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
Name: "{app}\{#MyAppExeName}"; Description: "Executar {#MyAppName}"; Flags: nowait postinstall skipifsilent

[Code]
procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
	DataDir: string;
	Answer: Integer;
begin
	if CurUninstallStep = usPostUninstall then
	begin
		DataDir := ExpandConstant('{#MyAppDataDir}');
		if DirExists(DataDir) then
		begin
			Answer := MsgBox(
				'Deseja remover tambem os dados locais do usuario (logs, relatorios, quarentena e configuracoes)?',
				mbConfirmation,
				MB_YESNO
			);
			if Answer = IDYES then
			begin
				DelTree(DataDir, True, True, True);
			end;
		end;
	end;
end;
