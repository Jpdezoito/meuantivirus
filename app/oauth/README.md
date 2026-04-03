# OAuth de E-mail Online

O SentinelaPC suporta leitura online em modo somente leitura para Gmail e Outlook.

## Arquivos esperados

- `gmail_oauth_client.json`
- `outlook_oauth_client.json`

Os arquivos reais nao sao versionados por seguranca. Use os modelos `.example.json` desta pasta.

## Gmail

1. Abra o Google Cloud Console.
2. Crie um projeto ou selecione um existente.
3. Ative a Gmail API.
4. Configure a tela de consentimento OAuth.
5. Crie uma credencial `OAuth client ID` do tipo `Desktop app`.
6. Salve o JSON baixado como `app/oauth/gmail_oauth_client.json`.

Escopos usados pelo app:

- `openid`
- `https://www.googleapis.com/auth/userinfo.email`
- `https://www.googleapis.com/auth/gmail.readonly`

## Outlook

1. Abra o Microsoft Entra Admin Center.
2. Registre um aplicativo.
3. Permita o tipo de conta que deseja aceitar.
4. Adicione permissoes delegadas `User.Read` e `Mail.Read`.
5. Copie o `Application (client) ID` para `app/oauth/outlook_oauth_client.json`.
6. Se quiser restringir o tenant, ajuste `tenant_id`; caso contrario use `common`.

Escopos usados pelo app:

- `openid`
- `offline_access`
- `User.Read`
- `Mail.Read`

## Observacoes

- O app so faz leitura da caixa; ele nao envia, move nem apaga mensagens.
- Os tokens locais ficam em `app/data/email_oauth/`.
- Se o token expirar ou a permissao for revogada, reconecte a conta no SentinelaPC.