"""Workers em background usados pela interface do SentinelaPC."""

from __future__ import annotations

from pathlib import Path
import traceback

from PySide6.QtCore import QObject, Signal, Slot

from app.services.diagnostics_service import DiagnosticsService
from app.services.browser_security_service import BrowserSecurityService
from app.services.browser_scan_models import BrowserScanReport
from app.services.audit_service import AuditService
from app.services.audit_models import AuditReport
from app.services.email_account_models import EmailProvider
from app.services.email_account_service import EmailAccountService
from app.services.email_security_service import EmailSecurityService
from app.services.email_scan_models import EmailScanReport
from app.services.file_scan_models import FileScanReport
from app.services.file_scanner_service import FileScannerService, ScanControl
from app.services.process_monitor_service import ProcessMonitorService
from app.services.process_scan_models import ProcessScanReport
from app.services.startup_inspector_service import StartupInspectorService
from app.services.startup_scan_models import StartupScanReport


class BackgroundWorkerBase(QObject):
    """Base simples para workers que reportam progresso, sucesso e falha."""

    finished = Signal(object)
    failed = Signal(str)
    progress = Signal(str)

    def _run_safely(self, operation_name: str, callback) -> None:
        """Executa a operacao e padroniza a mensagem de falha enviada para a UI."""
        try:
            result = callback()
        except Exception as error:
            error_type = type(error).__name__
            traceback.print_exc()
            self.failed.emit(f"{operation_name} falhou com {error_type}: {error}")
            return

        self.finished.emit(result)


class FileScanWorker(BackgroundWorkerBase):
    """Executa a varredura de arquivos em thread separada da interface."""

    progress_stats = Signal(int, int)

    def __init__(self, scanner: FileScannerService, target_directory: Path, scan_label: str) -> None:
        super().__init__()
        self.scanner = scanner
        self.target_directory = target_directory
        self.scan_label = scan_label
        self.scan_control = ScanControl()

    def toggle_pause(self) -> bool:
        """Alterna entre pausa e retomada da varredura."""
        if self.scan_control.is_paused():
            self.scan_control.request_resume()
            return False

        self.scan_control.request_pause()
        return True

    def request_cancel(self) -> None:
        """Solicita interrupcao cooperativa da varredura atual."""
        self.scan_control.request_cancel()

    @Slot()
    def run(self) -> None:
        """Dispara a analise e devolve o relatorio final para a interface."""
        self._run_safely(
            "A verificacao de arquivos",
            lambda: self.scanner.scan_path(
                self.target_directory,
                progress_callback=self.progress.emit,
                scan_label=self.scan_label,
                scan_control=self.scan_control,
                stats_callback=self.progress_stats.emit,
            ),
        )


class ProcessScanWorker(BackgroundWorkerBase):
    """Executa a verificacao de processos em thread separada da interface."""

    def __init__(self, process_monitor: ProcessMonitorService) -> None:
        super().__init__()
        self.process_monitor = process_monitor
        self.scan_control = ScanControl()

    def toggle_pause(self) -> bool:
        """Alterna entre pausa e retomada da verificacao de processos."""
        if self.scan_control.is_paused():
            self.scan_control.request_resume()
            return False

        self.scan_control.request_pause()
        return True

    def request_cancel(self) -> None:
        """Solicita interrupcao cooperativa da verificacao de processos."""
        self.scan_control.request_cancel()

    @Slot()
    def run(self) -> None:
        """Inicia a analise de processos e envia o relatorio final para a UI."""
        self._run_safely(
            "A verificacao de processos",
            lambda: self.process_monitor.scan_processes(
                progress_callback=self.progress.emit,
                scan_control=self.scan_control,
            ),
        )


class StartupScanWorker(BackgroundWorkerBase):
    """Executa a verificacao de inicializacao em thread separada da interface."""

    def __init__(self, startup_inspector: StartupInspectorService) -> None:
        super().__init__()
        self.startup_inspector = startup_inspector
        self.scan_control = ScanControl()

    def toggle_pause(self) -> bool:
        """Alterna entre pausa e retomada da verificacao de inicializacao."""
        if self.scan_control.is_paused():
            self.scan_control.request_resume()
            return False

        self.scan_control.request_pause()
        return True

    def request_cancel(self) -> None:
        """Solicita interrupcao cooperativa da verificacao de inicializacao."""
        self.scan_control.request_cancel()

    @Slot()
    def run(self) -> None:
        """Inicia a leitura das fontes de startup e envia o relatorio para a UI."""
        self._run_safely(
            "A verificacao de inicializacao",
            lambda: self.startup_inspector.inspect_startup(
                progress_callback=self.progress.emit,
                scan_control=self.scan_control,
            ),
        )


class DiagnosticsWorker(BackgroundWorkerBase):
    """Executa o diagnostico de saude do sistema em thread separada da interface."""

    def __init__(
        self,
        diagnostics_service: DiagnosticsService,
        startup_report: StartupScanReport | None,
        file_report: FileScanReport | None,
        process_report: ProcessScanReport | None,
    ) -> None:
        super().__init__()
        self.diagnostics_service = diagnostics_service
        self.startup_report = startup_report
        self.file_report = file_report
        self.process_report = process_report
        self.scan_control = ScanControl()

    def toggle_pause(self) -> bool:
        """Alterna entre pausa e retomada do diagnostico."""
        if self.scan_control.is_paused():
            self.scan_control.request_resume()
            return False

        self.scan_control.request_pause()
        return True

    def request_cancel(self) -> None:
        """Solicita interrupcao cooperativa do diagnostico."""
        self.scan_control.request_cancel()

    @Slot()
    def run(self) -> None:
        """Coleta o diagnostico e entrega o relatorio pronto para a interface."""
        self._run_safely(
            "O diagnostico do sistema",
            lambda: self.diagnostics_service.diagnose_system(
                startup_report=self.startup_report,
                file_report=self.file_report,
                process_report=self.process_report,
                progress_callback=self.progress.emit,
                scan_control=self.scan_control,
            ),
        )


class BrowserScanWorker(BackgroundWorkerBase):
    """Executa a analise de navegadores em thread separada."""

    def __init__(self, browser_service: BrowserSecurityService) -> None:
        super().__init__()
        self.browser_service = browser_service
        self.scan_control = ScanControl()

    def toggle_pause(self) -> bool:
        if self.scan_control.is_paused():
            self.scan_control.request_resume()
            return False

        self.scan_control.request_pause()
        return True

    def request_cancel(self) -> None:
        self.scan_control.request_cancel()

    @Slot()
    def run(self) -> None:
        self._run_safely(
            "A analise de navegadores",
            lambda: self.browser_service.analyze_browsers(
                progress_callback=self.progress.emit,
                scan_control=self.scan_control,
            ),
        )


class EmailScanWorker(BackgroundWorkerBase):
    """Executa a analise local de e-mails em thread separada."""

    def __init__(self, email_service: EmailSecurityService, sources: list[Path]) -> None:
        super().__init__()
        self.email_service = email_service
        self.sources = sources
        self.scan_control = ScanControl()

    def toggle_pause(self) -> bool:
        if self.scan_control.is_paused():
            self.scan_control.request_resume()
            return False

        self.scan_control.request_pause()
        return True

    def request_cancel(self) -> None:
        self.scan_control.request_cancel()

    @Slot()
    def run(self) -> None:
        self._run_safely(
            "A analise de e-mails",
            lambda: self.email_service.analyze_email_sources(
                self.sources,
                progress_callback=self.progress.emit,
                scan_control=self.scan_control,
            ),
        )


class EmailOnlineScanWorker(BackgroundWorkerBase):
    """Executa a analise online da caixa de e-mail em thread separada."""

    def __init__(self, account_service: EmailAccountService, provider: EmailProvider) -> None:
        super().__init__()
        self.account_service = account_service
        self.provider = provider
        self.scan_control = ScanControl()

    def toggle_pause(self) -> bool:
        if self.scan_control.is_paused():
            self.scan_control.request_resume()
            return False

        self.scan_control.request_pause()
        return True

    def request_cancel(self) -> None:
        self.scan_control.request_cancel()

    @Slot()
    def run(self) -> None:
        self._run_safely(
            "A analise online de e-mails",
            lambda: self.account_service.analyze_connected_inbox(
                self.provider,
                progress_callback=self.progress.emit,
                scan_control=self.scan_control,
            ),
        )


# Adicionado: worker para o novo modulo de Auditoria Avancada de Seguranca.
class AuditWorker(BackgroundWorkerBase):
    """Executa a auditoria avancada de seguranca em thread separada da interface.

    A auditoria nao suporta pausa, mas suporta cancelamento cooperativo entre
    grupos de checagens do servico.
    """

    def __init__(self, audit_service: AuditService) -> None:
        super().__init__()
        self.audit_service = audit_service
        self.scan_control = ScanControl()

    def request_cancel(self) -> None:
        """Solicita interrupcao cooperativa da auditoria avancada."""
        self.scan_control.request_cancel()

    @Slot()
    def run(self) -> None:
        """Executa a auditoria completa e entrega o relatorio para a UI."""
        self._run_safely(
            "A auditoria avancada de seguranca",
            lambda: self.audit_service.run_full_audit(
                progress_callback=self.progress.emit,
                scan_control=self.scan_control,
            ),
        )