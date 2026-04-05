# Distribuicao do SentinelaPC no Windows

Este guia entrega um fluxo profissional de distribuicao Windows com:

- build do executavel (`PyInstaller`, modo `onedir`);
- instalador (`Inno Setup`) com atalhos e desinstalacao;
- validacao pos-instalacao fora do ambiente de desenvolvimento.

## 1. Arquivos de build e instalacao

- `installer/requirements-build.txt`: dependencias de empacotamento.
- `installer/build_exe.ps1`: gera `dist/SentinelaPC/SentinelaPC.exe` com assets e modulos.
- `installer/SentinelaPC.iss`: script do instalador Inno Setup.
- `installer/build_installer.ps1`: compila o `.iss` via `ISCC.exe`.
- `installer/verify_install.ps1`: valida instalacao (arquivos, pastas e opcionalmente abre o app).
- `installer/version-info.txt`: metadados de versao do executavel.

## 2. Preparar ambiente

Na raiz do projeto:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m pip install -r installer\requirements-build.txt
```

## 3. Gerar executavel (PyInstaller)

Comando recomendado:

```powershell
.\installer\build_exe.ps1 -PythonExe ".\.venv\Scripts\python.exe" -InstallBuildDeps -Clean
```

Resultado esperado:

- `dist\SentinelaPC\SentinelaPC.exe`
- pacote completo `onedir` com `app`, `installer` e recursos visuais.

## 4. Gerar instalador Windows

Com Inno Setup 6 instalado:

```powershell
.\installer\build_installer.ps1 -AppVersion "0.1.0"
```

Resultado esperado:

- `dist\installer\SentinelaPC-Setup-0.1.0.exe`

## 5. Estrutura de instalacao

Executaveis:

- `{autopf}\SentinelaPC\`

Dados gravaveis do usuario (separados de `Program Files`):

- `{localappdata}\SentinelaPC\logs`
- `{localappdata}\SentinelaPC\reports`
- `{localappdata}\SentinelaPC\quarantine`
- `{localappdata}\SentinelaPC\app\data`
- `{localappdata}\SentinelaPC\config`

## 6. Atalhos e desinstalacao

O instalador cria:

- atalho no Menu Iniciar;
- atalho opcional na Area de Trabalho;
- entrada de desinstalacao no Windows.

Na desinstalacao:

- arquivos do programa e atalhos sao removidos automaticamente;
- dados do usuario em `LOCALAPPDATA\SentinelaPC` podem ser removidos opcionalmente por confirmacao.

## 7. Validacao pos-instalacao

Depois de instalar, execute:

```powershell
.\installer\verify_install.ps1 -Launch
```

Esse script valida:

- executavel instalado;
- assets essenciais (logo);
- pastas de logs, reports, quarantine e data;
- abertura do aplicativo fora do VS Code.

## 8. Caminhos absolutos e portabilidade

O app esta preparado para nao depender de caminhos fixos de desenvolvimento:

- recursos empacotados: baseados em `sys._MEIPASS`/diretorio do executavel;
- dados gravaveis: `LOCALAPPDATA\SentinelaPC` quando empacotado.

Arquivo-chave:

- `app/core/config.py`

## 9. Preparacao para evolucoes futuras

O instalador ja esta estruturado para expansoes como:

- opcao de inicializacao com Windows;
- modulos de monitoramento continuo;
- integracoes adicionais (ex.: browser bridge).

Essas evolucoes podem ser adicionadas no `.iss` sem quebrar o fluxo atual.

## 10. Fluxo final recomendado

1. `build_exe.ps1`
2. `build_installer.ps1`
3. instalar o `SentinelaPC-Setup-*.exe`
4. `verify_install.ps1 -Launch`
