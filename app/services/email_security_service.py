"""Servico de analise local de e-mails exportados e anexos selecionados."""

from __future__ import annotations

from collections.abc import Callable
from email import policy
from email.parser import BytesParser
import logging
from pathlib import Path
import re
import time

from app.core.heuristics import HeuristicEngine
from app.core.risk import ThreatClassification
from app.services.email_scan_models import EmailScanError, EmailScanItem, EmailScanReport
from app.services.file_scanner_service import ScanControl
from app.utils.logger import log_info


class EmailSecurityService:
    """Analisa arquivos de e-mail locais sem acessar contas ou dados sensiveis."""

    EMAIL_EXTENSIONS = {".eml", ".msg", ".txt"}
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

    def __init__(self, logger: logging.Logger, heuristic_engine: HeuristicEngine) -> None:
        self.logger = logger
        self.heuristic_engine = heuristic_engine

    def analyze_email_sources(
        self,
        sources: list[Path],
        progress_callback: Callable[[str], None] | None = None,
        scan_control: ScanControl | None = None,
    ) -> EmailScanReport:
        """Analisa arquivos de e-mail locais e pastas selecionadas pelo usuario."""
        self._emit_progress(progress_callback, "[E-mails] Iniciando analise local de e-mails exportados...")

        candidate_files = self._expand_sources(sources)
        results: list[EmailScanItem] = []
        errors: list[EmailScanError] = []
        inspected_items = 0

        for file_path in candidate_files:
            if not self._await_scan_control(scan_control, progress_callback):
                break

            inspected_items += 1
            item, error = self._analyze_email_file(file_path)
            if error is not None:
                errors.append(error)
                continue
            if item is not None:
                results.append(item)

        suspicious_items = sum(item.classification != ThreatClassification.TRUSTED for item in results)
        report = EmailScanReport(
            inspected_items=inspected_items,
            suspicious_items=suspicious_items,
            interrupted=scan_control.is_cancelled() if scan_control is not None else False,
            results=results,
            errors=errors,
        )
        log_info(
            self.logger,
            (
                "Analise de e-mails concluida | "
                f"itens={report.inspected_items} | suspeitos={report.suspicious_items} | erros={len(report.errors)}"
            ),
        )
        self._emit_progress(
            progress_callback,
            (
                "[E-mails] Analise concluida. "
                f"Itens avaliados: {report.inspected_items}. "
                f"Suspeitos: {report.suspicious_items}."
            ),
        )
        return report

    def _expand_sources(self, sources: list[Path]) -> list[Path]:
        files: list[Path] = []
        for source in sources:
            if source.is_file() and source.suffix.lower() in self.EMAIL_EXTENSIONS:
                files.append(source)
                continue

            if source.is_dir():
                for child in source.rglob("*"):
                    if child.is_file() and child.suffix.lower() in self.EMAIL_EXTENSIONS:
                        files.append(child)
        return files

    def _analyze_email_file(self, file_path: Path) -> tuple[EmailScanItem | None, EmailScanError | None]:
        try:
            if file_path.suffix.lower() == ".eml":
                sender, subject, body, attachments = self._parse_eml(file_path)
            else:
                sender, subject, body, attachments = self._parse_textual_email(file_path)
        except Exception as error:
            return None, EmailScanError(source=file_path, message=f"Falha ao ler arquivo: {error}")

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
            return None, None

        return (
            EmailScanItem(
                source_file=file_path,
                subject=subject or "(sem assunto)",
                sender=sender or "(remetente nao identificado)",
                links_found=len(links),
                attachments_found=len(attachments),
                score=evaluation.score,
                risk_level=evaluation.risk_level,
                classification=evaluation.classification,
                reasons=list(evaluation.reasons),
            ),
            None,
        )

    def _parse_eml(self, file_path: Path) -> tuple[str, str, str, list[str]]:
        with file_path.open("rb") as fh:
            message = BytesParser(policy=policy.default).parse(fh)

        sender = str(message.get("From") or "").strip()
        subject = str(message.get("Subject") or "").strip()
        body_parts: list[str] = []
        attachments: list[str] = []

        for part in message.walk():
            content_disposition = str(part.get_content_disposition() or "").lower()
            filename = part.get_filename()
            if filename:
                attachments.append(str(filename))

            if content_disposition == "attachment":
                continue

            if part.get_content_type() in {"text/plain", "text/html"}:
                try:
                    body_parts.append(part.get_content())
                except Exception:
                    continue

        body = "\n".join(body_parts)
        return sender, subject, body, attachments

    def _parse_textual_email(self, file_path: Path) -> tuple[str, str, str, list[str]]:
        text = file_path.read_text(encoding="utf-8", errors="ignore")

        sender_match = re.search(r"^(From|De):\s*(.+)$", text, re.IGNORECASE | re.MULTILINE)
        subject_match = re.search(r"^(Subject|Assunto):\s*(.+)$", text, re.IGNORECASE | re.MULTILINE)
        sender = sender_match.group(2).strip() if sender_match else ""
        subject = subject_match.group(2).strip() if subject_match else file_path.name

        attachment_matches = re.findall(r"([\w\-. ]+\.(?:exe|scr|bat|cmd|js|vbs|ps1|zip|rar|docm|xlsm))", text, re.IGNORECASE)
        return sender, subject, text, attachment_matches

    def extract_links_email(self, body: str) -> list[str]:
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
        if "@" not in sender_lower:
            return False
        domain = sender_lower.split("@")[-1]
        for brand in self.BRAND_KEYWORDS:
            if brand in domain and re.search(r"[0-9]", domain):
                return True
            if brand.replace("o", "0") in domain:
                return True
        return False

    def _await_scan_control(
        self,
        scan_control: ScanControl | None,
        progress_callback: Callable[[str], None] | None,
    ) -> bool:
        if scan_control is None:
            return True

        while scan_control.is_paused():
            self._emit_progress(progress_callback, "[E-mails] Analise pausada...")
            time.sleep(0.15)
            if scan_control.is_cancelled():
                return False

        return not scan_control.is_cancelled()

    def _emit_progress(self, progress_callback: Callable[[str], None] | None, message: str) -> None:
        if progress_callback is not None:
            progress_callback(message)
