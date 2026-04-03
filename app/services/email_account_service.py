"""Conexao OAuth e leitura online de e-mails para Gmail e Outlook."""

from __future__ import annotations

from collections.abc import Callable
import json
import logging
from pathlib import Path
import re
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from app.core.heuristics import HeuristicEngine
from app.core.risk import ThreatClassification
from app.services.email_account_models import (
    EmailAccountError,
    EmailAccountStatus,
    EmailOAuthConfigurationError,
    EmailOAuthDependencyError,
    EmailProvider,
)
from app.services.email_scan_models import EmailScanError, EmailScanItem, EmailScanReport
from app.services.file_scanner_service import ScanControl
from app.utils.logger import log_info


class EmailAccountService:
    """Gerencia conexao OAuth e leitura online read-only de provedores suportados."""

    GMAIL_SCOPES = (
        "openid",
        "https://www.googleapis.com/auth/userinfo.email",
        "https://www.googleapis.com/auth/gmail.readonly",
    )
    OUTLOOK_SCOPES = (
        "openid",
        "offline_access",
        "User.Read",
        "Mail.Read",
    )
    HIGH_RISK_ATTACHMENTS = {".exe", ".scr", ".bat", ".cmd", ".js", ".vbs", ".ps1", ".zip", ".rar"}
    BRAND_KEYWORDS = {"google", "microsoft", "paypal", "itau", "nubank", "bradesco", "caixa", "mercadopago"}
    URGENCY_KEYWORDS = {
        "urgente",
        "imediato",
        "suspensa",
        "bloqueada",
        "clique agora",
        "confirmar conta",
        "senha",
        "codigo",
        "pix",
        "pagamento",
    }

    def __init__(
        self,
        logger: logging.Logger,
        heuristic_engine: HeuristicEngine,
        runtime_data_dir: Path,
        resource_dir: Path,
    ) -> None:
        self.logger = logger
        self.heuristic_engine = heuristic_engine
        self.runtime_oauth_dir = runtime_data_dir / "email_oauth"
        self.resource_oauth_dir = resource_dir / "app" / "oauth"
        self.runtime_oauth_dir.mkdir(parents=True, exist_ok=True)

    def get_status(self, provider: EmailProvider) -> EmailAccountStatus:
        """Retorna o estado de conexao conhecido para o provedor solicitado."""
        if provider == EmailProvider.GMAIL:
            return self._get_gmail_status()
        return self._get_outlook_status()

    def connect(self, provider: EmailProvider) -> EmailAccountStatus:
        """Inicia a autenticacao OAuth interativa para o provedor."""
        if provider == EmailProvider.GMAIL:
            return self._connect_gmail()
        return self._connect_outlook()

    def disconnect(self, provider: EmailProvider) -> EmailAccountStatus:
        """Remove os tokens locais do provedor selecionado."""
        token_file = self._token_file(provider)
        if token_file.exists():
            token_file.unlink()

        if provider == EmailProvider.OUTLOOK:
            account_file = self._outlook_account_file()
            if account_file.exists():
                account_file.unlink()

        log_info(self.logger, f"Conexao de e-mail removida localmente | provider={provider.value}")
        return self.get_status(provider)

    def analyze_connected_inbox(
        self,
        provider: EmailProvider,
        *,
        max_messages: int = 25,
        progress_callback: Callable[[str], None] | None = None,
        scan_control: ScanControl | None = None,
    ) -> EmailScanReport:
        """Analisa a caixa online conectada em modo somente leitura."""
        self._emit_progress(progress_callback, f"[E-mails Online] Iniciando leitura online da caixa {provider.value}...")
        if provider == EmailProvider.GMAIL:
            return self._analyze_gmail_inbox(max_messages, progress_callback, scan_control)
        return self._analyze_outlook_inbox(max_messages, progress_callback, scan_control)

    def _connect_gmail(self) -> EmailAccountStatus:
        config_file = self.resource_oauth_dir / "gmail_oauth_client.json"
        if not config_file.exists():
            raise EmailOAuthConfigurationError(
                "Configuracao OAuth do Gmail ausente. Crie app/oauth/gmail_oauth_client.json com o client OAuth do Google."
            )

        try:
            from google.auth.transport.requests import Request as GoogleRequest
            from google.oauth2.credentials import Credentials
            from google_auth_oauthlib.flow import InstalledAppFlow
        except ImportError as error:
            raise EmailOAuthDependencyError(
                "Dependencias do Gmail OAuth nao estao instaladas. Rode pip install -r requirements.txt."
            ) from error

        token_file = self._token_file(EmailProvider.GMAIL)
        credentials = None
        if token_file.exists():
            credentials = Credentials.from_authorized_user_file(str(token_file), list(self.GMAIL_SCOPES))

        if credentials is None or not credentials.valid:
            if credentials and credentials.expired and credentials.refresh_token:
                credentials.refresh(GoogleRequest())
            else:
                flow = InstalledAppFlow.from_client_secrets_file(str(config_file), scopes=list(self.GMAIL_SCOPES))
                credentials = flow.run_local_server(port=0, open_browser=True)
            token_file.write_text(credentials.to_json(), encoding="utf-8")

        profile = self._gmail_get_profile(credentials.token)
        log_info(self.logger, f"Conta Gmail conectada | email={profile.get('emailAddress', '')}")
        return EmailAccountStatus(
            provider=EmailProvider.GMAIL,
            connected=True,
            account_label=profile.get("emailAddress", ""),
            config_present=True,
            scopes=self.GMAIL_SCOPES,
        )

    def _connect_outlook(self) -> EmailAccountStatus:
        config_file = self.resource_oauth_dir / "outlook_oauth_client.json"
        if not config_file.exists():
            raise EmailOAuthConfigurationError(
                "Configuracao OAuth do Outlook ausente. Crie app/oauth/outlook_oauth_client.json com o client_id do app Microsoft Entra."
            )

        try:
            import msal
        except ImportError as error:
            raise EmailOAuthDependencyError(
                "Dependencia MSAL nao instalada. Rode pip install -r requirements.txt."
            ) from error

        data = json.loads(config_file.read_text(encoding="utf-8"))
        client_id = str(data.get("client_id") or "").strip()
        tenant_id = str(data.get("tenant_id") or "common").strip() or "common"
        if not client_id:
            raise EmailOAuthConfigurationError("Arquivo outlook_oauth_client.json sem client_id.")

        cache = msal.SerializableTokenCache()
        cache_file = self._token_file(EmailProvider.OUTLOOK)
        if cache_file.exists():
            cache.deserialize(cache_file.read_text(encoding="utf-8"))

        authority = f"https://login.microsoftonline.com/{tenant_id}"
        app = msal.PublicClientApplication(client_id=client_id, authority=authority, token_cache=cache)
        result = app.acquire_token_interactive(scopes=list(self.OUTLOOK_SCOPES), prompt="select_account")
        if "access_token" not in result:
            raise EmailAccountError(result.get("error_description") or "Falha ao autenticar com Outlook via OAuth.")

        cache_file.write_text(cache.serialize(), encoding="utf-8")
        account_label = ""
        claims = result.get("id_token_claims") or {}
        if claims:
            account_label = str(claims.get("preferred_username") or claims.get("email") or "")
        if account_label:
            self._outlook_account_file().write_text(account_label, encoding="utf-8")

        log_info(self.logger, f"Conta Outlook conectada | conta={account_label}")
        return EmailAccountStatus(
            provider=EmailProvider.OUTLOOK,
            connected=True,
            account_label=account_label,
            config_present=True,
            scopes=self.OUTLOOK_SCOPES,
        )

    def _get_gmail_status(self) -> EmailAccountStatus:
        config_present = (self.resource_oauth_dir / "gmail_oauth_client.json").exists()
        token_file = self._token_file(EmailProvider.GMAIL)
        account_label = ""
        if token_file.exists():
            try:
                payload = json.loads(token_file.read_text(encoding="utf-8"))
                account_label = str(payload.get("account") or "")
            except Exception:
                account_label = ""
        return EmailAccountStatus(
            provider=EmailProvider.GMAIL,
            connected=token_file.exists(),
            account_label=account_label,
            config_present=config_present,
            scopes=self.GMAIL_SCOPES,
        )

    def _get_outlook_status(self) -> EmailAccountStatus:
        config_present = (self.resource_oauth_dir / "outlook_oauth_client.json").exists()
        token_file = self._token_file(EmailProvider.OUTLOOK)
        account_label = ""
        account_file = self._outlook_account_file()
        if account_file.exists():
            account_label = account_file.read_text(encoding="utf-8", errors="ignore").strip()
        return EmailAccountStatus(
            provider=EmailProvider.OUTLOOK,
            connected=token_file.exists(),
            account_label=account_label,
            config_present=config_present,
            scopes=self.OUTLOOK_SCOPES,
        )

    def _analyze_gmail_inbox(
        self,
        max_messages: int,
        progress_callback: Callable[[str], None] | None,
        scan_control: ScanControl | None,
    ) -> EmailScanReport:
        token = self._gmail_access_token()
        profile = self._gmail_get_profile(token)
        message_ids = self._gmail_list_messages(token, max_messages)
        results: list[EmailScanItem] = []
        errors: list[EmailScanError] = []

        for index, message_id in enumerate(message_ids, start=1):
            if not self._await_scan_control(scan_control, progress_callback):
                break
            self._emit_progress(progress_callback, f"[E-mails Online] Gmail: analisando mensagem {index}/{len(message_ids)}...")
            try:
                item = self._gmail_build_item(token, message_id, profile.get("emailAddress", ""))
            except Exception as error:
                errors.append(EmailScanError(source=Path(f"online/gmail/{message_id}"), message=str(error)))
                continue
            if item is not None:
                results.append(item)

        suspicious_items = sum(item.classification != ThreatClassification.TRUSTED for item in results)
        return EmailScanReport(
            inspected_items=len(message_ids),
            suspicious_items=suspicious_items,
            interrupted=scan_control.is_cancelled() if scan_control is not None else False,
            source_kind="online",
            provider=EmailProvider.GMAIL.value,
            results=results,
            errors=errors,
        )

    def _analyze_outlook_inbox(
        self,
        max_messages: int,
        progress_callback: Callable[[str], None] | None,
        scan_control: ScanControl | None,
    ) -> EmailScanReport:
        token = self._outlook_access_token()
        messages = self._outlook_list_messages(token, max_messages)
        results: list[EmailScanItem] = []
        errors: list[EmailScanError] = []

        for index, message in enumerate(messages, start=1):
            if not self._await_scan_control(scan_control, progress_callback):
                break
            self._emit_progress(progress_callback, f"[E-mails Online] Outlook: analisando mensagem {index}/{len(messages)}...")
            try:
                item = self._outlook_build_item(token, message)
            except Exception as error:
                message_id = str(message.get("id") or f"msg-{index}")
                errors.append(EmailScanError(source=Path(f"online/outlook/{message_id}"), message=str(error)))
                continue
            if item is not None:
                results.append(item)

        suspicious_items = sum(item.classification != ThreatClassification.TRUSTED for item in results)
        return EmailScanReport(
            inspected_items=len(messages),
            suspicious_items=suspicious_items,
            interrupted=scan_control.is_cancelled() if scan_control is not None else False,
            source_kind="online",
            provider=EmailProvider.OUTLOOK.value,
            results=results,
            errors=errors,
        )

    def _gmail_build_item(self, token: str, message_id: str, account_label: str) -> EmailScanItem | None:
        data = self._http_get_json(
            f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{message_id}?format=full",
            headers={"Authorization": f"Bearer {token}"},
        )
        payload = data.get("payload") or {}
        headers = {str(item.get("name") or "").lower(): str(item.get("value") or "") for item in payload.get("headers") or []}
        sender = headers.get("from", "")
        subject = headers.get("subject", "")
        body = str(data.get("snippet") or "")
        attachments = self._collect_gmail_attachment_names(payload)
        return self._build_scan_item(
            provider=EmailProvider.GMAIL,
            message_id=message_id,
            account_label=account_label,
            sender=sender,
            subject=subject,
            body=body,
            attachments=attachments,
        )

    def _outlook_build_item(self, token: str, message: dict[str, object]) -> EmailScanItem | None:
        message_id = str(message.get("id") or "sem-id")
        sender = str((((message.get("from") or {}) if isinstance(message.get("from"), dict) else {}).get("emailAddress") or {}) .get("address") or "")
        subject = str(message.get("subject") or "")
        body = str(message.get("bodyPreview") or "")
        attachments: list[str] = []
        if bool(message.get("hasAttachments")):
            attachment_data = self._http_get_json(
                f"https://graph.microsoft.com/v1.0/me/messages/{message_id}/attachments?$select=name",
                headers={"Authorization": f"Bearer {token}"},
            )
            attachments = [str(item.get("name") or "anexo") for item in attachment_data.get("value") or []]

        return self._build_scan_item(
            provider=EmailProvider.OUTLOOK,
            message_id=message_id,
            account_label="",
            sender=sender,
            subject=subject,
            body=body,
            attachments=attachments,
        )

    def _build_scan_item(
        self,
        *,
        provider: EmailProvider,
        message_id: str,
        account_label: str,
        sender: str,
        subject: str,
        body: str,
        attachments: list[str],
    ) -> EmailScanItem | None:
        links = self.extract_links_email(body)
        score, reasons = self.calculate_email_risk_score(
            sender=sender,
            subject=subject,
            body=body,
            links=links,
            attachments=attachments,
        )
        evaluation = self.heuristic_engine.build_custom_evaluation(score, reasons)
        if evaluation.classification == ThreatClassification.TRUSTED:
            return None

        source_label = f"Conta online {provider.value} | mensagem {message_id}"
        if account_label:
            source_label = f"Conta {account_label} | mensagem {message_id}"

        return EmailScanItem(
            source_file=Path(f"online/{provider.value}/{message_id}.txt"),
            source_label=source_label,
            subject=subject or "(sem assunto)",
            sender=sender or "(remetente nao identificado)",
            links_found=len(links),
            attachments_found=len(attachments),
            score=evaluation.score,
            risk_level=evaluation.risk_level,
            classification=evaluation.classification,
            source_kind="online",
            provider=provider.value,
            reasons=list(evaluation.reasons),
        )

    def extract_links_email(self, body: str) -> list[str]:
        """Extrai links de um corpo textual de mensagem online."""
        return re.findall(r"https?://[^\s\">]+", body, re.IGNORECASE)

    def calculate_email_risk_score(
        self,
        *,
        sender: str,
        subject: str,
        body: str,
        links: list[str],
        attachments: list[str],
    ) -> tuple[int, list[str]]:
        """Replica o score defensivo de phishing usado no modulo local."""
        score = 0
        reasons: list[str] = []

        lower_body = body.lower()
        lower_subject = subject.lower()
        sender_lower = sender.lower()

        for link in links:
            lower_link = link.lower()
            if any(shortener in lower_link for shortener in ("bit.ly", "tinyurl", "t.co", "is.gd")):
                score += 20
                reasons.append("Link encurtado detectado")
                break

        if self._has_brand_imitation(sender_lower):
            score += 35
            reasons.append("Dominio do remetente aparenta imitar marca conhecida")

        urgency_hits = sum(keyword in lower_body or keyword in lower_subject for keyword in self.URGENCY_KEYWORDS)
        if urgency_hits >= 2:
            score += 20
            reasons.append("Linguagem de urgencia e pressao detectada")
        elif urgency_hits == 1:
            score += 10
            reasons.append("Palavra-chave de urgencia detectada")

        for attachment in attachments:
            extension = Path(attachment).suffix.lower()
            if extension in self.HIGH_RISK_ATTACHMENTS:
                score += 35
                reasons.append("Anexo com extensao de alto risco")
                break

        if any(re.search(r"\.(pdf|doc|jpg|png)\.(exe|scr|bat|cmd)$", name, re.IGNORECASE) for name in attachments):
            score += 30
            reasons.append("Anexo com nome enganoso de dupla extensao")

        return score, reasons

    def _has_brand_imitation(self, sender_lower: str) -> bool:
        """Detecta dominios de remetente que imitam marcas conhecidas."""
        if "@" not in sender_lower:
            return False
        domain = sender_lower.split("@")[-1]
        for brand in self.BRAND_KEYWORDS:
            if brand in domain and re.search(r"[0-9]", domain):
                return True
            if brand.replace("o", "0") in domain:
                return True
        return False

    def _gmail_access_token(self) -> str:
        try:
            from google.auth.transport.requests import Request as GoogleRequest
            from google.oauth2.credentials import Credentials
        except ImportError as error:
            raise EmailOAuthDependencyError("Dependencias do Gmail OAuth nao estao instaladas.") from error

        token_file = self._token_file(EmailProvider.GMAIL)
        if not token_file.exists():
            raise EmailAccountError("Nenhuma conta Gmail conectada. Conecte a conta antes de analisar a caixa online.")

        credentials = Credentials.from_authorized_user_file(str(token_file), list(self.GMAIL_SCOPES))
        if credentials.expired and credentials.refresh_token:
            credentials.refresh(GoogleRequest())
            token_file.write_text(credentials.to_json(), encoding="utf-8")
        if not credentials.valid or not credentials.token:
            raise EmailAccountError("Token Gmail invalido ou expirado. Reconecte a conta para continuar.")
        return credentials.token

    def _outlook_access_token(self) -> str:
        try:
            import msal
        except ImportError as error:
            raise EmailOAuthDependencyError("Dependencia MSAL nao instalada.") from error

        config_file = self.resource_oauth_dir / "outlook_oauth_client.json"
        if not config_file.exists():
            raise EmailOAuthConfigurationError("Configuracao Outlook OAuth ausente.")
        config = json.loads(config_file.read_text(encoding="utf-8"))
        client_id = str(config.get("client_id") or "").strip()
        tenant_id = str(config.get("tenant_id") or "common").strip() or "common"
        if not client_id:
            raise EmailOAuthConfigurationError("Arquivo outlook_oauth_client.json sem client_id.")

        cache = msal.SerializableTokenCache()
        cache_file = self._token_file(EmailProvider.OUTLOOK)
        if not cache_file.exists():
            raise EmailAccountError("Nenhuma conta Outlook conectada. Conecte a conta antes de analisar a caixa online.")
        cache.deserialize(cache_file.read_text(encoding="utf-8"))
        app = msal.PublicClientApplication(
            client_id=client_id,
            authority=f"https://login.microsoftonline.com/{tenant_id}",
            token_cache=cache,
        )
        accounts = app.get_accounts()
        if not accounts:
            raise EmailAccountError("Cache Outlook sem conta autenticada. Reconecte a conta.")
        result = app.acquire_token_silent(scopes=list(self.OUTLOOK_SCOPES), account=accounts[0])
        if not result or "access_token" not in result:
            raise EmailAccountError("Nao foi possivel obter token silencioso do Outlook. Reconecte a conta.")
        cache_file.write_text(cache.serialize(), encoding="utf-8")
        return str(result["access_token"])

    def _gmail_get_profile(self, token: str) -> dict[str, object]:
        return self._http_get_json(
            "https://gmail.googleapis.com/gmail/v1/users/me/profile",
            headers={"Authorization": f"Bearer {token}"},
        )

    def _gmail_list_messages(self, token: str, max_messages: int) -> list[str]:
        data = self._http_get_json(
            f"https://gmail.googleapis.com/gmail/v1/users/me/messages?maxResults={max_messages}",
            headers={"Authorization": f"Bearer {token}"},
        )
        return [str(item.get("id") or "") for item in data.get("messages") or [] if item.get("id")]

    def _outlook_list_messages(self, token: str, max_messages: int) -> list[dict[str, object]]:
        query = urlencode({
            "$top": max_messages,
            "$select": "id,subject,from,bodyPreview,hasAttachments,receivedDateTime",
        })
        data = self._http_get_json(
            f"https://graph.microsoft.com/v1.0/me/messages?{query}",
            headers={"Authorization": f"Bearer {token}"},
        )
        return [item for item in data.get("value") or [] if isinstance(item, dict)]

    def _collect_gmail_attachment_names(self, payload: dict[str, object]) -> list[str]:
        attachments: list[str] = []

        def _walk(part: dict[str, object]) -> None:
            filename = str(part.get("filename") or "").strip()
            if filename:
                attachments.append(filename)
            for child in part.get("parts") or []:
                if isinstance(child, dict):
                    _walk(child)

        _walk(payload)
        return attachments

    def _http_get_json(self, url: str, *, headers: dict[str, str]) -> dict[str, object]:
        request = Request(url, headers=headers, method="GET")
        try:
            with urlopen(request, timeout=30) as response:
                payload = response.read().decode("utf-8")
        except HTTPError as error:
            detail = error.read().decode("utf-8", errors="ignore")
            raise EmailAccountError(f"Falha HTTP {error.code} ao acessar provedor de e-mail: {detail or error.reason}") from error
        except URLError as error:
            raise EmailAccountError(f"Falha de rede ao acessar provedor de e-mail: {error.reason}") from error

        try:
            return json.loads(payload)
        except json.JSONDecodeError as error:
            raise EmailAccountError("Resposta invalida recebida do provedor de e-mail.") from error

    def _token_file(self, provider: EmailProvider) -> Path:
        return self.runtime_oauth_dir / f"{provider.value}_token.json"

    def _outlook_account_file(self) -> Path:
        return self.runtime_oauth_dir / "outlook_account.txt"

    def _await_scan_control(
        self,
        scan_control: ScanControl | None,
        progress_callback: Callable[[str], None] | None,
    ) -> bool:
        if scan_control is None:
            return True
        while scan_control.is_paused():
            self._emit_progress(progress_callback, "[E-mails Online] Analise pausada...")
            time.sleep(0.15)
            if scan_control.is_cancelled():
                return False
        if scan_control.is_cancelled():
            return False
        return True

    def _emit_progress(self, progress_callback: Callable[[str], None] | None, message: str) -> None:
        if progress_callback is not None:
            progress_callback(message)