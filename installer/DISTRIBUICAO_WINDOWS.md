# Distribuicao do SentinelaPC no Windows

Este guia prepara o projeto para desenvolvimento local e geracao de executavel com PyInstaller.

## 1. Requirements do projeto

Arquivo criado:

- `requirements.txt`: dependencias reais de execucao.
- `installer/requirements-build.txt`: dependencias de build, incluindo PyInstaller.

## 2. Criar ambiente virtual

Na raiz do projeto:

```powershell
cd "C:\Users\José Paulo Siqueira\Desktop\antvirus\SentinelaPC"
python -m venv .venv
```

Se quiser ativar o ambiente no PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
```

## 3. Instalar dependencias

Somente dependencias de execucao:

```powershell
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

Dependencias para build do executavel:

```powershell
python -m pip install --upgrade pip
python -m pip install -r installer\requirements-build.txt
```

## 4. Executar em modo desenvolvimento

Com o ambiente virtual ativo:

```powershell
python main.py
```

Sem ativar o ambiente:

```powershell
.\.venv\Scripts\python.exe main.py
```

## 5. Gerar .exe com PyInstaller

Instale primeiro as dependencias de build e depois rode o comando abaixo na raiz do projeto.

```powershell
python -m PyInstaller --noconfirm --clean --windowed --name SentinelaPC --paths . --add-data "app;app" main.py
```

Observacao importante:

- para o instalador com Inno Setup, prefira manter o modo padrao `onedir`, porque ele gera `dist\SentinelaPC\` com todos os arquivos prontos para copia.

## 6. Comando inicial recomendado do PyInstaller

Com ambiente virtual local:

```powershell
.\.venv\Scripts\python.exe -m PyInstaller --noconfirm --clean --windowed --name SentinelaPC --paths . --add-data "app;app" main.py
```

Script pronto alternativo:

```powershell
.\installer\build_exe.ps1
```

## 7. Tratamento basico de caminhos no executavel

O projeto foi ajustado para diferenciar:

- caminho de recursos: usado para localizar o codigo e arquivos empacotados pelo PyInstaller;
- caminho de runtime: usado para banco, logs, relatorios e quarentena.

Com isso:

- em desenvolvimento, tudo continua sendo salvo na pasta do projeto;
- no executavel, os dados gravaveis passam a usar a pasta ao lado do `.exe`, evitando escrita dentro do diretorio temporario do PyInstaller.

Arquivo ajustado:

- `app/core/config.py`

## 8. Resultado esperado do build

Depois do build, o PyInstaller normalmente gera:

- `dist\SentinelaPC\SentinelaPC.exe` no modo padrao `onedir`
- `build\` com arquivos temporarios do processo

## 9. Observacoes importantes para Windows

- Execute o PowerShell com permissao adequada se quiser testar quarentena e restauracao em pastas protegidas.
- O Windows Defender pode inspecionar o executavel gerado por ser um build local sem assinatura digital.
- Se futuramente voce adicionar icone `.ico`, o comando pode receber `--icon caminho\arquivo.ico`.

## 10. Instalador com Inno Setup

Arquivo criado:

- `installer\SentinelaPC.iss`

### O que este script faz

- instala o programa em `Program Files`;
- cria atalho no Menu Iniciar;
- oferece atalho opcional na Area de Trabalho;
- cria as pastas `logs`, `quarantine`, `reports` e `app\data` em `LOCALAPPDATA\SentinelaPC`;
- usa um `AppId` fixo para facilitar futuras atualizacoes.

### Fluxo recomendado antes de gerar o instalador

1. Gere o build `onedir` com PyInstaller.
2. Confirme que a pasta `dist\SentinelaPC\` existe.
3. Abra o arquivo `installer\SentinelaPC.iss` no Inno Setup Compiler.
4. Compile o instalador.

### Como compilar o instalador no Inno Setup

No Inno Setup Compiler, abra o script:

```powershell
installer\SentinelaPC.iss
```

Se quiser compilar pela linha de comando, um exemplo comum e:

```powershell
"C:\Program Files (x86)\Inno Setup 6\ISCC.exe" "installer\SentinelaPC.iss"
```

### Observacoes importantes para empacotamento antes do instalador

- gere primeiro o build com PyInstaller; o Inno Setup nao substitui essa etapa;
- o script pressupoe o executavel em `dist\SentinelaPC\SentinelaPC.exe`;
- como o aplicativo agora usa `LOCALAPPDATA\SentinelaPC` quando esta empacotado, ele nao depende de permissao de escrita em `Program Files`;
- mantenha o mesmo `AppId` no script `.iss` nas proximas versoes para que upgrades funcionem corretamente;
- quando houver icone `.ico`, inclua tanto no PyInstaller quanto em `SetupIconFile` no Inno Setup.
