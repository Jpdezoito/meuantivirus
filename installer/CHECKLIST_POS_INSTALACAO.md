# Checklist Pos-Instalacao - SentinelaPC (Windows)

Use este checklist apos gerar e executar o instalador.

## 1) Validacao do instalador

1. Execute o arquivo `SentinelaPC-Setup-<versao>.exe`.
2. Confirme que o assistente mostra o nome `SentinelaPC`.
3. Confirme que o instalador usa o icone oficial.
4. Instale em `C:\Program Files\SentinelaPC` (padrao).

Resultado esperado:
- Instalacao concluida sem erro.
- Opcao de executar o app ao final disponivel.

## 2) Validacao da abertura do aplicativo

1. Abra o app pelo atalho do Menu Iniciar.
2. Abra o app pelo atalho da Area de Trabalho (se criado).
3. Abra o app diretamente por `C:\Program Files\SentinelaPC\SentinelaPC.exe`.

Resultado esperado:
- A interface do SentinelaPC abre normalmente.
- Nenhuma janela de PowerShell/terminal aparece na inicializacao.

## 3) Validacao de icones

1. Verifique icone do executavel instalado.
2. Verifique icone do atalho do Menu Iniciar.
3. Verifique icone do atalho da Area de Trabalho.

Resultado esperado:
- Mesmo icone oficial em todos os pontos.

## 4) Validacao de estrutura de pastas

1. Confirme a pasta de programa:
   - `C:\Program Files\SentinelaPC`
2. Confirme pastas gravaveis em usuario:
   - `%LOCALAPPDATA%\SentinelaPC\logs`
   - `%LOCALAPPDATA%\SentinelaPC\reports`
   - `%LOCALAPPDATA%\SentinelaPC\quarantine`
   - `%LOCALAPPDATA%\SentinelaPC\app\data`
   - `%LOCALAPPDATA%\SentinelaPC\config`

Resultado esperado:
- Todas as pastas existem.
- O app funciona sem tentar gravar em Program Files para dados dinamicos.

## 5) Validacao funcional basica

1. Abra o app e confirme carregamento de assets (logo e elementos visuais).
2. Execute uma verificacao rapida de teste.
3. Gere um relatorio de teste.

Resultado esperado:
- Sem erro de caminho de asset.
- Sem dependencias de pasta de desenvolvimento (Desktop/VS Code).

## 6) Validacao de desinstalacao

1. Desinstale por `Aplicativos e Recursos` ou atalho `Desinstalar SentinelaPC`.
2. Confirme remocao dos atalhos.
3. Confirme remocao do diretorio de programa.
4. Na pergunta final, valide os dois cenarios:
   - manter dados do usuario
   - remover dados do usuario

Resultado esperado:
- Desinstalacao limpa.
- Comportamento conforme escolha do usuario para dados locais.

## 7) Comando de verificacao automatica (opcional)

Apos instalar, rode:

```powershell
.\installer\verify_install.ps1 -Launch
```

Resultado esperado:
- Script retorna validacao concluida.
- Aplicativo abre para teste manual.
