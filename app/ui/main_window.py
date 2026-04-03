"""Janela principal reorganizada com navegacao lateral e paginas dedicadas."""

from __future__ import annotations

import ctypes
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from uuid import uuid4

from PySide6.QtCore import QThread, QTimer
from PySide6.QtGui import QCloseEvent
from PySide6.QtWidgets import (
    QApplication,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QMessageBox,
    QStackedWidget,
    QStatusBar,
    QVBoxLayout,
    QWidget,
)

from app.core.bootstrap import ApplicationContext
from app.core.config import APP_NAME, APP_VERSION
from app.data.history_models import HistoryRecordInput
from app.data.history_repository import HistoryRepository
from app.data.action_event_models import ActionEventRecordInput
from app.data.action_event_repository import ActionEventRepository
from app.services.browser_scan_models import BrowserScanReport
from app.services.browser_security_service import BrowserSecurityService
from app.services.audit_service import AuditService
from app.services.audit_models import AuditReport, AuditStatus
from app.services.diagnostics_models import SystemDiagnosticsReport
from app.services.diagnostics_service import DiagnosticsService
from app.services.email_account_models import EmailAccountError, EmailOAuthConfigurationError, EmailOAuthDependencyError, EmailProvider
from app.services.email_account_service import EmailAccountService
from app.services.email_scan_models import EmailScanReport
from app.services.email_security_service import EmailSecurityService
from app.services.file_scan_models import FileScanReport
from app.services.file_scanner_service import FileScannerService
from app.services.process_monitor_service import ProcessMonitorService
from app.services.process_scan_models import ProcessScanReport
from app.services.quarantine_service import QuarantineService
from app.services.report_models import SessionReportData
from app.services.report_service import ReportService
from app.services.startup_inspector_service import StartupInspectorService
from app.services.startup_scan_models import StartupScanReport
from app.ui.navigation import SidebarNavigation
from app.ui.pages import DashboardPage, HistoryPage, OperationPage, QuarantinePage, ReportsPage
from app.ui.pages import AuditPage
from app.ui.action_policy import ActionPolicy, ActionSeverity, build_action_policy
from app.ui.browser_suspicious_dialog import BrowserSuspiciousItemsDialog
from app.ui.confirmation_dialogs import AdminPermissionDialog, ConfirmActionDialog
from app.ui.quarantine_dialogs import (
    ProcessQuarantineSelectionDialog,
    QuarantineSelectionDialog,
    StartupQuarantineSelectionDialog,
)
from app.ui.workers import (
    BrowserScanWorker,
    DiagnosticsWorker,
    EmailOnlineScanWorker,
    EmailScanWorker,
    FileScanWorker,
    ProcessScanWorker,
    StartupScanWorker,
)
from app.ui.workers import AuditWorker
from app.utils.logger import log_error, log_info, log_warning


class MainWindow(QMainWindow):
    """Janela principal modularizada com navegacao lateral e multiplas telas."""

    def __init__(self, context: ApplicationContext) -> None:
        super().__init__()
        self.context = context
        self.file_scanner = FileScannerService(context.logger, context.heuristic_engine)
        self.browser_security_service = BrowserSecurityService(context.logger, context.heuristic_engine)
        self.email_security_service = EmailSecurityService(context.logger, context.heuristic_engine)
        self.email_account_service = EmailAccountService(
            context.logger,
            context.heuristic_engine,
            context.paths.data_dir,
            context.paths.resource_dir,
        )
        # Adicionado: servico de auditoria avancada de seguranca.
        self.audit_service = AuditService(
            context.logger,
            browser_service=self.browser_security_service,
            email_service=self.email_security_service,
        )
        self.process_monitor = ProcessMonitorService(context.logger, context.heuristic_engine)
        self.startup_inspector = StartupInspectorService(context.logger, context.heuristic_engine)
        self.diagnostics_service = DiagnosticsService(context.logger, self.startup_inspector)
        self.quarantine_service = QuarantineService(
            context.paths.quarantine_dir,
            context.paths.database_file,
            context.logger,
        )
        self.report_service = ReportService(context.paths.reports_dir, context.logger)
        self.history_repository = HistoryRepository(context.paths.database_file)
        self.action_event_repository = ActionEventRepository(context.paths.database_file)

        self.scan_thread: QThread | None = None
        self.scan_worker: FileScanWorker | None = None
        self.process_thread: QThread | None = None
        self.process_worker: ProcessScanWorker | None = None
        self.startup_thread: QThread | None = None
        self.startup_worker: StartupScanWorker | None = None
        self.diagnostics_thread: QThread | None = None
        self.diagnostics_worker: DiagnosticsWorker | None = None
        self.browser_thread: QThread | None = None
        self.browser_worker: BrowserScanWorker | None = None
        self.email_thread: QThread | None = None
        self.email_worker: EmailScanWorker | EmailOnlineScanWorker | None = None
        # Adicionado: thread e worker para auditoria avancada.
        self.audit_thread: QThread | None = None
        self.audit_worker: AuditWorker | None = None

        self.last_file_scan_report: FileScanReport | None = None
        self.last_process_scan_report: ProcessScanReport | None = None
        self.last_startup_scan_report: StartupScanReport | None = None
        self.last_diagnostics_report: SystemDiagnosticsReport | None = None
        self.last_browser_scan_report: BrowserScanReport | None = None
        self.last_email_scan_report: EmailScanReport | None = None
        # Adicionado: ultimo relatorio de auditoria avancada gerado na sessao.
        self.last_audit_report: AuditReport | None = None
        self.session_quarantine_items: list = []
        self.executed_scan_types: list[str] = []
        self._active_operation_page_id = "dashboard"
        self._current_file_scan_display_name = "Verificacao rapida"
        self._current_file_scan_history_label = "Verificacao rapida de arquivos"
        self._is_file_scan_paused = False
        self._is_process_scan_paused = False
        self._is_startup_scan_paused = False
        self._is_diagnostics_paused = False
        self._is_browser_scan_paused = False
        self._is_email_scan_paused = False
        self._active_email_scan_correlation_id: str | None = None
        self._active_email_scan_summary = ""
        self._active_email_scan_policy: ActionPolicy | None = None
        self._connected_email_provider: EmailProvider | None = None
        # Adicionado: estado da auditoria avancada (sem pausa; apenas cancelamento).
        self._is_audit_running = False
        self._current_file_scan_analyzed = 0
        self._current_file_scan_suspicious = 0
        self._visual_progress_timer = QTimer(self)
        self._visual_progress_timer.setInterval(230)
        self._visual_progress_timer.timeout.connect(self._tick_visual_progress)
        self._visual_progress_value = 0
        self._visual_progress_page_id: str | None = None
        self._visual_progress_paused = False

        self.setWindowTitle(f"{APP_NAME} {APP_VERSION}")
        self.resize(1460, 900)

        self._build_pages()
        self._build_ui()
        self._connect_signals()
        self._populate_initial_logs()
        self._switch_page("dashboard")
        self._set_file_scan_control_actions(False)
        self._set_process_scan_control_actions(False)
        self._set_startup_scan_control_actions(False)
        self._set_diagnostics_control_actions(False)
        self._set_browser_scan_control_actions(False)
        self._set_email_scan_control_actions(False)
        # Adicionado: inicializa controles da auditoria avancada.
        self._set_audit_control_actions(False)

    def _build_pages(self) -> None:
        """Instancia as paginas especializadas usadas pela area central da interface."""
        self.dashboard_page = DashboardPage(self.context)
        self.files_page = OperationPage(
            "Analise de superficies",
            "Arquivos suspeitos",
            "Execute verificacoes de arquivos, acompanhe o resultado detalhado e envie itens sinalizados para quarentena manualmente.",
            [
                ("quick_scan", "Verificar arquivos suspeitos"),
                ("full_scan", "Verificacao completa"),
                ("pause_scan", "Pausar / retomar scan"),
                ("stop_scan", "Parar scan"),
                ("quarantine_file", "Mandar pra quarentena"),
            ],
        )
        self.processes_page = OperationPage(
            "Monitoramento de atividade",
            "Processos",
            "Veja o resultado da leitura dos processos ativos com foco em consumo e sinais operacionais suspeitos.",
            [
                ("process_scan", "Verificar processos"),
                ("pause_process_scan", "Pausar / retomar scan"),
                ("stop_process_scan", "Parar scan"),
                ("quarantine_process", "Mandar pra quarentena"),
            ],
        )
        self.startup_page = OperationPage(
            "Persistencia de inicializacao",
            "Inicializacao",
            "Acompanhe programas e itens configurados para iniciar com o Windows, com leitura desacoplada e segura.",
            [
                ("startup_scan", "Verificar inicializacao"),
                ("pause_startup_scan", "Pausar / retomar scan"),
                ("stop_startup_scan", "Parar scan"),
                ("quarantine_startup", "Mandar pra quarentena"),
            ],
        )
        self.browsers_page = OperationPage(
            "Seguranca de navegacao",
            "Navegadores",
            "Analise local de executaveis, extensoes, sinais de hijack e downloads perigosos sem acessar dados privados.",
            [
                ("browser_scan", "Analisar navegadores"),
                ("browser_view_suspicious", "Ver itens suspeitos"),
                ("pause_browser_scan", "Pausar / retomar scan"),
                ("stop_browser_scan", "Parar scan"),
            ],
        )
        self.emails_page = OperationPage(
            "Protecao de mensagens",
            "E-mails",
            "Conecte Gmail ou Outlook com OAuth somente leitura e analise mensagens online ou arquivos exportados em busca de phishing e anexos perigosos.",
            [
                ("email_oauth_help", "Como configurar OAuth"),
                ("email_connect_gmail", "Conectar Gmail"),
                ("email_connect_outlook", "Conectar Outlook"),
                ("email_scan_online", "Analisar caixa online"),
                ("email_disconnect_account", "Desconectar conta"),
                ("email_scan_file", "Analisar e-mails (arquivo)"),
                ("email_scan_folder", "Analisar e-mails (pasta)"),
                ("pause_email_scan", "Pausar / retomar scan"),
                ("stop_email_scan", "Parar scan"),
            ],
        )
        self.audit_page = AuditPage()
        self.quarantine_page = QuarantinePage()
        self.reports_page = ReportsPage()
        self.history_page = HistoryPage()
        self.diagnostics_page = OperationPage(
            "Saude do equipamento",
            "Diagnostico",
            "Analise CPU, memoria, disco, startup, processos pesados e sinais simples de lentidao sem travar a interface.",
            [
                ("diagnostics", "Executar diagnostico"),
                ("pause_diagnostics", "Pausar / retomar diagnostico"),
                ("stop_diagnostics", "Parar diagnostico"),
                ("quarantine_file", "Mandar pra quarentena (arquivos)"),
                ("quarantine_process", "Mandar pra quarentena (processos)"),
                ("quarantine_startup", "Mandar pra quarentena (inicializacao)"),
            ],
        )

        self.page_stack = QStackedWidget()
        self.page_stack.addWidget(self.dashboard_page)
        self.page_stack.addWidget(self.files_page)
        self.page_stack.addWidget(self.processes_page)
        self.page_stack.addWidget(self.startup_page)
        self.page_stack.addWidget(self.browsers_page)
        self.page_stack.addWidget(self.emails_page)
        self.page_stack.addWidget(self.audit_page)
        self.page_stack.addWidget(self.quarantine_page)
        self.page_stack.addWidget(self.reports_page)
        self.page_stack.addWidget(self.history_page)
        self.page_stack.addWidget(self.diagnostics_page)

        self.pages = {
            "dashboard": self.dashboard_page,
            "files": self.files_page,
            "processes": self.processes_page,
            "startup": self.startup_page,
            "browsers": self.browsers_page,
            "emails": self.emails_page,
            "audit": self.audit_page,
            "quarantine": self.quarantine_page,
            "reports": self.reports_page,
            "history": self.history_page,
            "diagnostics": self.diagnostics_page,
        }

    def _build_ui(self) -> None:
        """Monta a janela principal com barra lateral e empilhamento de paginas."""
        self.sidebar = SidebarNavigation()

        content_area = QWidget()
        content_area.setObjectName("contentArea")
        content_layout = QVBoxLayout(content_area)
        content_layout.setContentsMargins(24, 20, 24, 20)
        content_layout.setSpacing(16)
        content_layout.addWidget(self.page_stack, 1)

        shell = QWidget(self)
        shell_layout = QHBoxLayout(shell)
        shell_layout.setContentsMargins(0, 0, 0, 0)
        shell_layout.setSpacing(0)
        shell_layout.addWidget(self.sidebar)
        shell_layout.addWidget(content_area, 1)

        self.setCentralWidget(shell)
        self.setStatusBar(self._build_status_bar())

    def _build_status_bar(self) -> QStatusBar:
        """Cria a barra inferior com status de execucao e versao da aplicacao."""
        status_bar = QStatusBar(self)
        status_bar.showMessage("Pronto para iniciar verificacoes e diagnosticos.")
        status_bar.addPermanentWidget(QLabel(f"Versao {APP_VERSION}"))
        return status_bar

    def _connect_signals(self) -> None:
        """Liga navegacao e botoes das paginas ao roteador principal de acoes."""
        self.sidebar.page_selected.connect(self._switch_page)
        self.dashboard_page.action_requested.connect(self._handle_action_request)
        self.files_page.action_requested.connect(self._handle_action_request)
        self.processes_page.action_requested.connect(self._handle_action_request)
        self.startup_page.action_requested.connect(self._handle_action_request)
        self.browsers_page.action_requested.connect(self._handle_action_request)
        self.emails_page.action_requested.connect(self._handle_action_request)
        self.audit_page.action_requested.connect(self._handle_action_request)
        self.quarantine_page.action_requested.connect(self._handle_action_request)
        self.reports_page.action_requested.connect(self._handle_action_request)
        self.history_page.action_requested.connect(self._handle_action_request)
        self.diagnostics_page.action_requested.connect(self._handle_action_request)

    def _populate_initial_logs(self) -> None:
        """Registra as primeiras mensagens no dashboard ao abrir a aplicacao."""
        self.dashboard_page.append_activity(
            [
                "[Inicializacao] Interface profissional carregada com sucesso.",
                f"[Inicializacao] Banco configurado em: {self.context.paths.database_file}",
                f"[Inicializacao] Pasta de quarentena pronta em: {self.context.paths.quarantine_dir}",
                f"[Inicializacao] Pasta de relatorios pronta em: {self.context.paths.reports_dir}",
                f"[Inicializacao] Log diario ativo em: {self.context.paths.daily_log_file}",
            ]
        )

    def _switch_page(self, page_id: str) -> None:
        """Alterna a tela central e atualiza dados dependentes quando necessario."""
        widget = self.pages.get(page_id)
        if widget is None:
            return

        self.page_stack.setCurrentWidget(widget)
        self.sidebar.set_current_page(page_id)

        if page_id == "quarantine":
            self._refresh_quarantine_page()
        elif page_id == "history":
            self._refresh_history_page()

    def _handle_action_request(self, action_key: str) -> None:
        """Roteia as acoes disparadas pelas paginas e pela barra lateral auxiliar."""
        if action_key == "quick_scan":
            self._start_quick_scan()
            return
        if action_key == "full_scan":
            self._start_full_scan()
            return
        if action_key == "pause_scan":
            self._toggle_file_scan_pause()
            return
        if action_key == "stop_scan":
            self._stop_file_scan()
            return
        if action_key == "process_scan":
            self._start_process_scan()
            return
        if action_key == "pause_process_scan":
            self._toggle_process_scan_pause()
            return
        if action_key == "stop_process_scan":
            self._stop_process_scan()
            return
        if action_key == "quarantine_process":
            self._open_process_quarantine_selection()
            return
        if action_key == "startup_scan":
            self._start_startup_scan()
            return
        if action_key == "browser_scan":
            self._start_browser_scan()
            return
        if action_key == "browser_view_suspicious":
            self._show_browser_suspicious_items()
            return
        if action_key == "pause_browser_scan":
            self._toggle_browser_scan_pause()
            return
        if action_key == "stop_browser_scan":
            self._stop_browser_scan()
            return
        if action_key == "email_scan_file":
            self._start_email_scan_file()
            return
        if action_key == "email_oauth_help":
            self._show_email_oauth_setup_guide()
            return
        if action_key == "email_connect_gmail":
            self._connect_email_provider(EmailProvider.GMAIL)
            return
        if action_key == "email_connect_outlook":
            self._connect_email_provider(EmailProvider.OUTLOOK)
            return
        if action_key == "email_scan_online":
            self._start_email_online_scan()
            return
        if action_key == "email_disconnect_account":
            self._disconnect_email_provider()
            return
        if action_key == "email_scan_folder":
            self._start_email_scan_folder()
            return
        if action_key == "pause_email_scan":
            self._toggle_email_scan_pause()
            return
        if action_key == "stop_email_scan":
            self._stop_email_scan()
            return
        if action_key == "audit_run":
            self._start_audit()
            return
        if action_key == "audit_stop":
            self._stop_audit()
            return
        if action_key == "audit_resolve":
            self._resolve_audit_problems()
            return
        if action_key == "export_audit_txt":
            self._export_audit_report("txt")
            return
        if action_key == "export_audit_json":
            self._export_audit_report("json")
            return
        if action_key == "pause_startup_scan":
            self._toggle_startup_scan_pause()
            return
        if action_key == "stop_startup_scan":
            self._stop_startup_scan()
            return
        if action_key == "quarantine_startup":
            self._open_startup_quarantine_selection()
            return
        if action_key == "diagnostics":
            self._start_diagnostics()
            return
        if action_key == "pause_diagnostics":
            self._toggle_diagnostics_pause()
            return
        if action_key == "stop_diagnostics":
            self._stop_diagnostics()
            return
        if action_key == "quarantine_file":
            self._open_quarantine_selection()
            return
        if action_key == "open_dashboard":
            self._switch_page("dashboard")
            return
        if action_key == "open_audit":
            self._switch_page("audit")
            return
        if action_key == "open_files":
            self._switch_page("files")
            return
        if action_key in {"open_quarantine", "refresh_quarantine"}:
            self._switch_page("quarantine")
            return
        if action_key == "restore_quarantine":
            self._restore_selected_quarantine_item()
            return
        if action_key == "delete_quarantine":
            self._delete_selected_quarantine_item()
            return
        if action_key in {"open_history", "refresh_history"}:
            self._switch_page("history")
            return
        if action_key == "generate_report":
            self._generate_session_report()
            return

        self.statusBar().showMessage(f"Acao solicitada: {action_key}")
        self.dashboard_page.append_activity([f"[Acao] {action_key} solicitada pela interface."])

    def closeEvent(self, event: QCloseEvent) -> None:
        """Evita fechar a janela durante verificacoes para preservar integridade da sessao."""
        if self._has_active_background_task():
            QMessageBox.warning(
                self,
                "Operacao em andamento",
                "Aguarde o termino da verificacao atual antes de fechar o SentinelaPC.",
            )
            event.ignore()
            return

        super().closeEvent(event)

    def _start_quick_scan(self) -> None:
        """Solicita a pasta ao usuario e executa a verificacao de arquivos em background."""
        if self._has_active_background_task():
            self._append_to_page("files", ["[Scanner] Ja existe uma operacao em andamento."])
            log_warning(self.context.logger, "Tentativa de iniciar verificacao rapida com outra operacao ativa.")
            return

        selected_directory = QFileDialog.getExistingDirectory(
            self,
            "Selecione a pasta para verificacao rapida",
            str(self.context.paths.base_dir),
        )
        if not selected_directory:
            self._append_to_page("files", ["[Scanner] Selecao de pasta cancelada pelo usuario."])
            log_info(self.context.logger, "Selecao de pasta cancelada na verificacao rapida.")
            return

        self._start_file_scan(
            target_directory=Path(selected_directory),
            display_name="Verificacao rapida",
            history_label="Verificacao rapida de arquivos",
            initial_lines=[
                "[Scanner] Verificacao rapida iniciada.",
                f"[Scanner] Pasta selecionada: {Path(selected_directory)}",
            ],
        )

    def _start_full_scan(self) -> None:
        """Executa uma verificacao completa a partir da raiz do disco atual do Windows."""
        if self._has_active_background_task():
            self._append_to_page("files", ["[Scanner] Ja existe uma operacao em andamento."])
            log_warning(self.context.logger, "Tentativa de iniciar verificacao completa com outra operacao ativa.")
            return

        target_directory = Path(self.context.paths.base_dir.anchor) if self.context.paths.base_dir.anchor else Path.home()
        policy = build_action_policy(
            action_id="full_scan_start",
            title="Iniciar verificacao completa",
            description=(
                "A verificacao completa pode levar bastante tempo, percorrer muitas pastas e gerar erros de acesso esperados em areas protegidas do Windows."
            ),
            severity=ActionSeverity.HIGH,
            confirm_label="Iniciar verificacao completa",
            detail_lines=(
                "A operacao tenta ler toda a raiz do disco atual.",
                "Durante a analise, outros scans nao poderao ser iniciados.",
                "Erros de acesso sao registrados em log e nao interrompem o processo por si so.",
            ),
        )
        correlation_id = self._confirm_sensitive_action(
            policy,
            target_summary=f"Destino da analise: {target_directory}",
        )
        if correlation_id is None:
            self._append_to_page("files", ["[Scanner] Verificacao completa cancelada pelo usuario."])
            return

        self._record_action_event(
            policy,
            target_summary=str(target_directory),
            decision="approved",
            status="started",
            details="Verificacao completa iniciada pela interface.",
            correlation_id=correlation_id,
        )

        self._start_file_scan(
            target_directory=target_directory,
            display_name="Verificacao completa",
            history_label="Verificacao completa de arquivos",
            initial_lines=[
                "[Scanner] Verificacao completa iniciada.",
                f"[Scanner] Pasta raiz analisada: {target_directory}",
                "[Scanner] O console exibira o avanco por pasta e por arquivo durante a execucao.",
            ],
        )

    def _start_file_scan(
        self,
        target_directory: Path,
        display_name: str,
        history_label: str,
        initial_lines: list[str],
    ) -> None:
        """Inicializa qualquer varredura de arquivos preservando um fluxo unico de UI."""
        self._current_file_scan_display_name = display_name
        self._current_file_scan_history_label = history_label
        self._is_file_scan_paused = False
        self._current_file_scan_analyzed = 0
        self._current_file_scan_suspicious = 0
        self._prepare_operation_page("files", initial_lines)
        self.files_page.update_summary(0, 0, datetime.now().strftime("%H:%M:%S"))
        self._start_visual_progress("files", display_name)
        self.statusBar().showMessage(f"Executando {display_name.lower()}...")
        self._set_busy_actions(False)
        self._set_file_scan_control_actions(True)
        log_info(self.context.logger, f"{history_label} iniciada pela interface em: {target_directory}")

        self.scan_thread = QThread(self)
        self.scan_worker = FileScanWorker(self.file_scanner, target_directory, history_label)
        self.scan_worker.moveToThread(self.scan_thread)
        self._connect_background_worker(
            thread=self.scan_thread,
            worker=self.scan_worker,
            success_handler=self._handle_scan_finished,
            failure_handler=self._handle_scan_failed,
            cleanup_handler=self._cleanup_scan_thread,
        )
        self.scan_worker.progress_stats.connect(self._update_file_scan_progress_summary)
        self.scan_thread.start()

    def _toggle_file_scan_pause(self) -> None:
        """Pausa ou retoma a verificacao de arquivos em andamento."""
        if self.scan_worker is None or self.scan_thread is None:
            self._append_to_page("files", ["[Scanner] Nenhuma verificacao de arquivos esta em andamento."])
            return

        self._is_file_scan_paused = self.scan_worker.toggle_pause()
        self._set_visual_progress_paused(self._is_file_scan_paused)
        if self._is_file_scan_paused:
            message = "[Scanner] Pausa solicitada. A verificacao sera pausada no proximo ponto seguro."
            self.statusBar().showMessage("Pausa solicitada para a verificacao de arquivos.")
        else:
            message = "[Scanner] Retomada solicitada. A verificacao continuara de onde parou."
            self.statusBar().showMessage("Verificacao de arquivos retomada.")

        self._append_to_page("files", [message])

    def _stop_file_scan(self) -> None:
        """Solicita interrupcao cooperativa da verificacao de arquivos em andamento."""
        if self.scan_worker is None or self.scan_thread is None:
            self._append_to_page("files", ["[Scanner] Nenhuma verificacao de arquivos esta em andamento."])
            return

        confirmation = QMessageBox.question(
            self,
            "Parar verificacao",
            "Deseja interromper a verificacao atual e manter apenas o resultado parcial coletado ate agora?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if confirmation != QMessageBox.StandardButton.Yes:
            return

        self.scan_worker.request_cancel()
        self._is_file_scan_paused = False
        self._set_visual_progress_paused(False)
        self._append_to_page("files", ["[Scanner] Interrupcao solicitada. Encerrando a verificacao no proximo ponto seguro..."])
        self.statusBar().showMessage("Interrupcao solicitada para a verificacao de arquivos.")

    def _start_process_scan(self) -> None:
        """Executa a verificacao de processos em background preservando responsividade."""
        if self._has_active_background_task():
            self._append_to_page("processes", ["[Processos] Ja existe uma operacao em andamento."])
            log_warning(self.context.logger, "Tentativa de iniciar verificacao de processos com outra operacao ativa.")
            return

        self._prepare_operation_page(
            "processes",
            [
                "[Processos] Verificacao de processos iniciada.",
                "[Processos] Coletando dados dos processos ativos do sistema...",
            ],
        )
        self.processes_page.update_summary(0, 0, datetime.now().strftime("%H:%M:%S"))
        self.statusBar().showMessage("Executando verificacao de processos...")
        self._set_busy_actions(False)
        self._is_process_scan_paused = False
        self._start_visual_progress("processes", "Verificacao de processos")
        self._set_process_scan_control_actions(True)
        log_info(self.context.logger, "Verificacao de processos iniciada pela interface.")

        self.process_thread = QThread(self)
        self.process_worker = ProcessScanWorker(self.process_monitor)
        self.process_worker.moveToThread(self.process_thread)
        self._connect_background_worker(
            thread=self.process_thread,
            worker=self.process_worker,
            success_handler=self._handle_process_scan_finished,
            failure_handler=self._handle_process_scan_failed,
            cleanup_handler=self._cleanup_process_thread,
        )
        self.process_thread.start()

    def _toggle_process_scan_pause(self) -> None:
        """Pausa ou retoma a verificacao de processos em andamento."""
        if self.process_worker is None or self.process_thread is None:
            self._append_to_page("processes", ["[Processos] Nenhuma verificacao de processos esta em andamento."])
            return

        self._is_process_scan_paused = self.process_worker.toggle_pause()
        self._set_visual_progress_paused(self._is_process_scan_paused)
        if self._is_process_scan_paused:
            message = "[Processos] Pausa solicitada. A verificacao sera pausada no proximo ponto seguro."
            self.statusBar().showMessage("Pausa solicitada para a verificacao de processos.")
        else:
            message = "[Processos] Retomada solicitada. A verificacao continuara de onde parou."
            self.statusBar().showMessage("Verificacao de processos retomada.")

        self._append_to_page("processes", [message])

    def _stop_process_scan(self) -> None:
        """Solicita interrupcao cooperativa da verificacao de processos em andamento."""
        if self.process_worker is None or self.process_thread is None:
            self._append_to_page("processes", ["[Processos] Nenhuma verificacao de processos esta em andamento."])
            return

        confirmation = QMessageBox.question(
            self,
            "Parar verificacao de processos",
            "Deseja interromper a verificacao de processos atual e manter apenas o resultado parcial?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if confirmation != QMessageBox.StandardButton.Yes:
            return

        self.process_worker.request_cancel()
        self._is_process_scan_paused = False
        self._set_visual_progress_paused(False)
        self._append_to_page("processes", ["[Processos] Interrupcao solicitada. Encerrando a verificacao no proximo ponto seguro..."])
        self.statusBar().showMessage("Interrupcao solicitada para a verificacao de processos.")

    def _start_startup_scan(self) -> None:
        """Executa a verificacao das fontes de inicializacao em background."""
        if self._has_active_background_task():
            self._append_to_page("startup", ["[Inicializacao] Ja existe uma operacao em andamento."])
            log_warning(self.context.logger, "Tentativa de iniciar verificacao de inicializacao com outra operacao ativa.")
            return

        self._prepare_operation_page(
            "startup",
            [
                "[Inicializacao] Verificacao de inicializacao iniciada.",
                "[Inicializacao] Lendo pasta Startup, Registro e tarefas agendadas...",
            ],
        )
        self.startup_page.update_summary(0, 0, datetime.now().strftime("%H:%M:%S"))
        self.statusBar().showMessage("Executando verificacao de inicializacao...")
        self._set_busy_actions(False)
        self._is_startup_scan_paused = False
        self._start_visual_progress("startup", "Verificacao de inicializacao")
        self._set_startup_scan_control_actions(True)
        log_info(self.context.logger, "Verificacao de inicializacao iniciada pela interface.")

        self.startup_thread = QThread(self)
        self.startup_worker = StartupScanWorker(self.startup_inspector)
        self.startup_worker.moveToThread(self.startup_thread)
        self._connect_background_worker(
            thread=self.startup_thread,
            worker=self.startup_worker,
            success_handler=self._handle_startup_scan_finished,
            failure_handler=self._handle_startup_scan_failed,
            cleanup_handler=self._cleanup_startup_thread,
        )
        self.startup_thread.start()

    def _toggle_startup_scan_pause(self) -> None:
        """Pausa ou retoma a verificacao de inicializacao em andamento."""
        if self.startup_worker is None or self.startup_thread is None:
            self._append_to_page("startup", ["[Inicializacao] Nenhuma verificacao de inicializacao esta em andamento."])
            return

        self._is_startup_scan_paused = self.startup_worker.toggle_pause()
        self._set_visual_progress_paused(self._is_startup_scan_paused)
        if self._is_startup_scan_paused:
            message = "[Inicializacao] Pausa solicitada. A verificacao sera pausada no proximo ponto seguro."
            self.statusBar().showMessage("Pausa solicitada para a verificacao de inicializacao.")
        else:
            message = "[Inicializacao] Retomada solicitada. A verificacao continuara de onde parou."
            self.statusBar().showMessage("Verificacao de inicializacao retomada.")

        self._append_to_page("startup", [message])

    def _stop_startup_scan(self) -> None:
        """Solicita interrupcao cooperativa da verificacao de inicializacao em andamento."""
        if self.startup_worker is None or self.startup_thread is None:
            self._append_to_page("startup", ["[Inicializacao] Nenhuma verificacao de inicializacao esta em andamento."])
            return

        confirmation = QMessageBox.question(
            self,
            "Parar verificacao de inicializacao",
            "Deseja interromper a verificacao de inicializacao atual e manter apenas o resultado parcial?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if confirmation != QMessageBox.StandardButton.Yes:
            return

        self.startup_worker.request_cancel()
        self._is_startup_scan_paused = False
        self._set_visual_progress_paused(False)
        self._append_to_page("startup", ["[Inicializacao] Interrupcao solicitada. Encerrando a verificacao no proximo ponto seguro..."])
        self.statusBar().showMessage("Interrupcao solicitada para a verificacao de inicializacao.")

    def _start_browser_scan(self) -> None:
        """Executa a analise de seguranca de navegadores em background."""
        if self._has_active_background_task():
            self._append_to_page("browsers", ["[Navegadores] Ja existe uma operacao em andamento."])
            return

        self._prepare_operation_page(
            "browsers",
            [
                "[Navegadores] Analise iniciada.",
                "[Navegadores] Verificando executaveis, extensoes, hijack e downloads suspeitos...",
            ],
        )
        self.browsers_page.update_summary(0, 0, datetime.now().strftime("%H:%M:%S"))
        self.statusBar().showMessage("Executando analise de navegadores...")
        self._set_busy_actions(False)
        self._is_browser_scan_paused = False
        self._start_visual_progress("browsers", "Analise de navegadores")
        self._set_browser_scan_control_actions(True)

        self.browser_thread = QThread(self)
        self.browser_worker = BrowserScanWorker(self.browser_security_service)
        self.browser_worker.moveToThread(self.browser_thread)
        self._connect_background_worker(
            thread=self.browser_thread,
            worker=self.browser_worker,
            success_handler=self._handle_browser_scan_finished,
            failure_handler=self._handle_browser_scan_failed,
            cleanup_handler=self._cleanup_browser_thread,
        )
        self.browser_thread.start()

    def _toggle_browser_scan_pause(self) -> None:
        """Pausa ou retoma a analise de navegadores em andamento."""
        if self.browser_worker is None or self.browser_thread is None:
            self._append_to_page("browsers", ["[Navegadores] Nenhuma analise de navegadores esta em andamento."])
            return

        self._is_browser_scan_paused = self.browser_worker.toggle_pause()
        self._set_visual_progress_paused(self._is_browser_scan_paused)
        if self._is_browser_scan_paused:
            self._append_to_page("browsers", ["[Navegadores] Pausa solicitada."])
            self.statusBar().showMessage("Pausa solicitada para analise de navegadores.")
            return

        self._append_to_page("browsers", ["[Navegadores] Retomada solicitada."])
        self.statusBar().showMessage("Analise de navegadores retomada.")

    def _stop_browser_scan(self) -> None:
        """Solicita interrupcao cooperativa da analise de navegadores."""
        if self.browser_worker is None or self.browser_thread is None:
            self._append_to_page("browsers", ["[Navegadores] Nenhuma analise de navegadores esta em andamento."])
            return

        self.browser_worker.request_cancel()
        self._is_browser_scan_paused = False
        self._set_visual_progress_paused(False)
        self._append_to_page("browsers", ["[Navegadores] Interrupcao solicitada. Encerrando no proximo ponto seguro..."])
        self.statusBar().showMessage("Interrupcao solicitada para analise de navegadores.")

    def _show_browser_suspicious_items(self) -> None:
        """Abre dialogo com tabela e acoes rapidas para os suspeitos do ultimo scan de navegadores."""
        report = self.last_browser_scan_report
        if report is None:
            QMessageBox.information(
                self,
                "Sem dados",
                "Execute a analise de navegadores primeiro para visualizar os itens suspeitos.",
            )
            return

        if not report.results:
            QMessageBox.information(
                self,
                "Nenhum item suspeito",
                "O ultimo scan de navegadores nao encontrou itens suspeitos.",
            )
            return

        dialog = BrowserSuspiciousItemsDialog(list(report.results), self)
        dialog.exec()

    def _start_email_scan_file(self) -> None:
        """Inicia analise local de um ou mais arquivos de e-mail selecionados."""
        selected_files, _ = QFileDialog.getOpenFileNames(
            self,
            "Selecione os arquivos de e-mail",
            str(self.context.paths.base_dir),
            "Arquivos de e-mail (*.eml *.msg *.txt)",
        )
        if not selected_files:
            self._append_to_page("emails", ["[E-mails] Selecao de arquivos cancelada."])
            return

        self._start_email_scan([Path(item) for item in selected_files], "arquivo(s) selecionado(s)")

    def _start_email_scan_folder(self) -> None:
        """Inicia analise local de uma pasta contendo e-mails exportados."""
        selected_directory = QFileDialog.getExistingDirectory(
            self,
            "Selecione a pasta com e-mails exportados",
            str(self.context.paths.base_dir),
        )
        if not selected_directory:
            self._append_to_page("emails", ["[E-mails] Selecao de pasta cancelada."])
            return

        self._start_email_scan([Path(selected_directory)], "pasta selecionada")

    def _connect_email_provider(self, provider: EmailProvider) -> None:
        """Solicita consentimento e inicia a conexao OAuth com Gmail ou Outlook."""
        if self._has_active_background_task():
            self._append_to_page("emails", ["[E-mails] Aguarde o termino da operacao atual antes de conectar uma conta online."])
            return

        status = self.email_account_service.get_status(provider)
        if not status.config_present:
            self._show_email_oauth_setup_guide(provider)
            self._append_to_page(
                "emails",
                [f"[E-mails] Configuracao OAuth de {provider.value.capitalize()} ausente. Guia de setup exibido ao usuario."],
            )
            return

        policy = build_action_policy(
            action_id=f"email_connect_{provider.value}",
            title=f"Autorizar conexao online com {provider.value.capitalize()}",
            description=(
                "O SentinelaPC vai abrir o fluxo OAuth do provedor para solicitar acesso somente leitura aos e-mails da conta escolhida."
            ),
            severity=ActionSeverity.SENSITIVE,
            confirm_label="Continuar com OAuth",
            detail_lines=(
                "A autenticacao ocorre no provedor oficial, nao dentro do app.",
                "O acesso solicitado e de leitura de e-mails, sem envio nem alteracao da caixa.",
                "Voce podera desconectar a conta depois no proprio SentinelaPC.",
            ),
        )
        target_summary = f"Provedor escolhido: {provider.value.capitalize()}"
        correlation_id = self._confirm_sensitive_action(policy, target_summary=target_summary)
        if correlation_id is None:
            self._append_to_page("emails", [f"[E-mails] Conexao com {provider.value.capitalize()} cancelada antes do OAuth."])
            return

        try:
            status = self.email_account_service.connect(provider)
        except (EmailOAuthConfigurationError, EmailOAuthDependencyError, EmailAccountError) as error:
            self._record_action_event(policy, target_summary, "approved", "failed", str(error), correlation_id)
            QMessageBox.warning(self, "Falha ao conectar conta", str(error))
            self._append_to_page("emails", [f"[E-mails] Falha ao conectar {provider.value.capitalize()}: {error}"])
            return
        except Exception as error:
            self._record_action_event(policy, target_summary, "approved", "failed", f"Erro inesperado: {error}", correlation_id)
            log_error(self.context.logger, "Falha inesperada ao conectar conta de e-mail online.", error)
            QMessageBox.critical(self, "Falha ao conectar conta", f"Nao foi possivel concluir a conexao OAuth: {error}")
            return

        self._connected_email_provider = provider if status.connected else None
        account_label = status.account_label or provider.value.capitalize()
        self._record_action_event(policy, target_summary, "approved", "succeeded", f"Conta conectada: {account_label}", correlation_id)
        self._append_to_page("emails", [f"[E-mails] Conta online conectada com sucesso: {account_label}"])
        self.statusBar().showMessage(f"Conta {provider.value.capitalize()} conectada com sucesso.")

    def _show_email_oauth_setup_guide(self, provider: EmailProvider | None = None) -> None:
        """Exibe um guia rapido para configurar OAuth de Gmail e Outlook."""
        guide_title = "Como configurar OAuth para e-mails online"
        provider_label = "Gmail e Outlook"
        provider_steps = (
            "1. Abra a pasta app/oauth do projeto.\n"
            "2. Use os arquivos .example.json como modelo.\n"
            "3. Crie seus arquivos reais gmail_oauth_client.json e/ou outlook_oauth_client.json.\n"
            "4. Volte ao SentinelaPC e clique em conectar conta."
        )

        if provider == EmailProvider.GMAIL:
            provider_label = "Gmail"
            provider_steps = (
                "1. No Google Cloud Console, crie um projeto ou use um existente.\n"
                "2. Ative a Gmail API.\n"
                "3. Crie uma credencial OAuth Client ID do tipo Desktop App.\n"
                "4. Salve o JSON em app/oauth/gmail_oauth_client.json usando o arquivo .example.json como referencia.\n"
                "5. Volte ao app e clique em Conectar Gmail."
            )
        elif provider == EmailProvider.OUTLOOK:
            provider_label = "Outlook"
            provider_steps = (
                "1. No Microsoft Entra Admin Center, registre um aplicativo.\n"
                "2. Permita conta pessoal/organizacional conforme sua necessidade.\n"
                "3. Adicione permissoes delegadas User.Read e Mail.Read.\n"
                "4. Copie o client_id para app/oauth/outlook_oauth_client.json usando o arquivo .example.json como referencia.\n"
                "5. Volte ao app e clique em Conectar Outlook."
            )

        message = (
            f"Provedor: {provider_label}\n\n"
            f"{provider_steps}\n\n"
            "Arquivos de apoio no projeto:\n"
            "- app/oauth/README.md\n"
            "- app/oauth/gmail_oauth_client.example.json\n"
            "- app/oauth/outlook_oauth_client.example.json\n\n"
            "Escopo usado pelo SentinelaPC: somente leitura de e-mails."
        )
        QMessageBox.information(self, guide_title, message)

    def _disconnect_email_provider(self) -> None:
        """Desconecta a conta online atualmente selecionada no modulo de e-mails."""
        provider = self._connected_email_provider or self._resolve_connected_email_provider()
        if provider is None:
            QMessageBox.information(self, "Sem conta conectada", "Nenhuma conta online de e-mail esta conectada no momento.")
            return

        policy = build_action_policy(
            action_id="email_disconnect_account",
            title="Desconectar conta online de e-mail",
            description="Os tokens locais da conta serao removidos do computador e o app deixara de acessar a caixa online ate nova autenticacao.",
            severity=ActionSeverity.SENSITIVE,
            confirm_label="Desconectar conta",
        )
        target_summary = f"Conta conectada: {provider.value.capitalize()}"
        correlation_id = self._confirm_sensitive_action(policy, target_summary=target_summary)
        if correlation_id is None:
            return

        status = self.email_account_service.disconnect(provider)
        self._connected_email_provider = None if not status.connected else provider
        self._record_action_event(policy, target_summary, "approved", "succeeded", "Tokens locais removidos com sucesso.", correlation_id)
        self._append_to_page("emails", [f"[E-mails] Conta {provider.value.capitalize()} desconectada do aplicativo."])
        self.statusBar().showMessage(f"Conta {provider.value.capitalize()} desconectada.")

    def _start_email_online_scan(self) -> None:
        """Executa a analise online read-only da caixa de e-mails conectada."""
        if self._has_active_background_task():
            self._append_to_page("emails", ["[E-mails] Ja existe uma operacao em andamento."])
            return

        provider = self._connected_email_provider or self._resolve_connected_email_provider()
        if provider is None:
            QMessageBox.information(
                self,
                "Conta nao conectada",
                "Conecte primeiro uma conta Gmail ou Outlook para analisar a caixa online.",
            )
            return

        target_summary = f"Leitura online da caixa conectada: {provider.value.capitalize()}"
        policy = build_action_policy(
            action_id="email_scan_online_inbox",
            title="Autorizar leitura online da caixa de e-mails",
            description="O SentinelaPC vai consultar a caixa online em modo somente leitura para analisar mensagens recentes em busca de phishing e anexos suspeitos.",
            severity=ActionSeverity.SENSITIVE,
            confirm_label="Ler caixa online",
            detail_lines=(
                "A leitura ocorre com escopo somente leitura.",
                "Nenhuma mensagem sera enviada, movida ou apagada.",
                "A verificacao foca em remetente, assunto, links, anexos e indicadores de phishing.",
            ),
        )
        correlation_id = self._confirm_sensitive_action(policy, target_summary=target_summary)
        if correlation_id is None:
            self._append_to_page("emails", ["[E-mails] Leitura online cancelada antes da abertura da caixa."])
            return

        self._active_email_scan_policy = policy
        self._active_email_scan_correlation_id = correlation_id
        self._active_email_scan_summary = target_summary
        self._record_action_event(policy, target_summary, "approved", "started", "Analise online da caixa iniciada apos consentimento do usuario.", correlation_id)

        self._prepare_operation_page(
            "emails",
            [
                "[E-mails Online] Analise da caixa online iniciada.",
                f"[E-mails Online] Provedor conectado: {provider.value.capitalize()}",
                "[E-mails Online] Lendo mensagens recentes em modo somente leitura...",
            ],
        )
        self.emails_page.update_summary(0, 0, datetime.now().strftime("%H:%M:%S"))
        self.statusBar().showMessage(f"Executando analise online de e-mails em {provider.value.capitalize()}...")
        self._set_busy_actions(False)
        self._is_email_scan_paused = False
        self._start_visual_progress("emails", "Analise online de e-mails")
        self._set_email_scan_control_actions(True)

        self.email_thread = QThread(self)
        self.email_worker = EmailOnlineScanWorker(self.email_account_service, provider)
        self.email_worker.moveToThread(self.email_thread)
        self._connect_background_worker(
            thread=self.email_thread,
            worker=self.email_worker,
            success_handler=self._handle_email_scan_finished,
            failure_handler=self._handle_email_scan_failed,
            cleanup_handler=self._cleanup_email_thread,
        )
        self.email_thread.start()

    def _start_email_scan(self, sources: list[Path], origin_label: str) -> None:
        """Executa analise local de e-mails em background."""
        if self._has_active_background_task():
            self._append_to_page("emails", ["[E-mails] Ja existe uma operacao em andamento."])
            return

        target_summary = self._build_email_sources_summary(sources, origin_label)
        policy = build_action_policy(
            action_id="email_scan_open_and_analyze",
            title="Autorizar leitura local de e-mails",
            description=(
                "O SentinelaPC vai abrir localmente os arquivos de e-mail selecionados em modo somente leitura para verificar remetente, assunto, links e anexos suspeitos. Nenhum conteudo sera enviado para fora do computador."
            ),
            severity=ActionSeverity.SENSITIVE,
            confirm_label="Autorizar analise",
            detail_lines=(
                "A leitura acontece apenas nos arquivos e pastas que voce selecionou.",
                "O aplicativo nao acessa contas online nem altera o conteudo do e-mail.",
                "A verificacao procura sinais de phishing, links suspeitos e anexos perigosos.",
            ),
            success_message="Analise local de e-mails autorizada.",
        )
        correlation_id = self._confirm_sensitive_action(policy, target_summary=target_summary)
        if correlation_id is None:
            self._append_to_page("emails", ["[E-mails] Permissao negada. Nenhum arquivo de e-mail foi aberto para analise."])
            return

        self._active_email_scan_policy = policy
        self._active_email_scan_correlation_id = correlation_id
        self._active_email_scan_summary = target_summary
        self._record_action_event(
            policy,
            target_summary,
            "approved",
            "started",
            "Analise local de e-mails iniciada apos autorizacao do usuario.",
            correlation_id,
        )

        self._prepare_operation_page(
            "emails",
            [
                "[E-mails] Analise local iniciada.",
                f"[E-mails] Origem: {origin_label}",
                "[E-mails] Verificando links, anexos e sinais de phishing sem acessar contas...",
            ],
        )
        self.emails_page.update_summary(0, 0, datetime.now().strftime("%H:%M:%S"))
        self.statusBar().showMessage("Executando analise de e-mails...")
        self._set_busy_actions(False)
        self._is_email_scan_paused = False
        self._start_visual_progress("emails", "Analise de e-mails")
        self._set_email_scan_control_actions(True)

        self.email_thread = QThread(self)
        self.email_worker = EmailScanWorker(self.email_security_service, sources)
        self.email_worker.moveToThread(self.email_thread)
        self._connect_background_worker(
            thread=self.email_thread,
            worker=self.email_worker,
            success_handler=self._handle_email_scan_finished,
            failure_handler=self._handle_email_scan_failed,
            cleanup_handler=self._cleanup_email_thread,
        )
        self.email_thread.start()

    def _toggle_email_scan_pause(self) -> None:
        """Pausa ou retoma a analise local de e-mails em andamento."""
        if self.email_worker is None or self.email_thread is None:
            self._append_to_page("emails", ["[E-mails] Nenhuma analise de e-mails esta em andamento."])
            return

        self._is_email_scan_paused = self.email_worker.toggle_pause()
        self._set_visual_progress_paused(self._is_email_scan_paused)
        if self._is_email_scan_paused:
            self._append_to_page("emails", ["[E-mails] Pausa solicitada."])
            self.statusBar().showMessage("Pausa solicitada para analise de e-mails.")
            return

        self._append_to_page("emails", ["[E-mails] Retomada solicitada."])
        self.statusBar().showMessage("Analise de e-mails retomada.")

    def _stop_email_scan(self) -> None:
        """Solicita interrupcao cooperativa da analise de e-mails."""
        if self.email_worker is None or self.email_thread is None:
            self._append_to_page("emails", ["[E-mails] Nenhuma analise de e-mails esta em andamento."])
            return

        self.email_worker.request_cancel()
        self._is_email_scan_paused = False
        self._set_visual_progress_paused(False)
        self._append_to_page("emails", ["[E-mails] Interrupcao solicitada. Encerrando no proximo ponto seguro..."])
        self.statusBar().showMessage("Interrupcao solicitada para analise de e-mails.")

    def _start_audit(self) -> None:
        """Executa a auditoria avancada de seguranca em background."""
        if self._has_active_background_task():
            self.statusBar().showMessage("Ja existe uma operacao em andamento.")
            return

        self._switch_page("audit")
        self._active_operation_page_id = "audit"
        self.audit_page.clear_results()
        self._start_visual_progress("audit", "Auditoria avancada")
        self.statusBar().showMessage("Executando auditoria avancada de seguranca...")
        self._set_busy_actions(False)
        self._is_audit_running = True
        self._set_audit_control_actions(True)

        self.audit_thread = QThread(self)
        self.audit_worker = AuditWorker(self.audit_service)
        self.audit_worker.moveToThread(self.audit_thread)
        self._connect_background_worker(
            thread=self.audit_thread,
            worker=self.audit_worker,
            success_handler=self._handle_audit_finished,
            failure_handler=self._handle_audit_failed,
            cleanup_handler=self._cleanup_audit_thread,
        )
        self.audit_thread.start()

    def _stop_audit(self) -> None:
        """Solicita interrupcao cooperativa da auditoria avancada."""
        if self.audit_worker is None or self.audit_thread is None:
            self.statusBar().showMessage("Nenhuma auditoria avancada esta em andamento.")
            return

        self.audit_worker.request_cancel()
        self.statusBar().showMessage("Interrupcao solicitada para a auditoria avancada.")

    def _handle_audit_finished(self, report: AuditReport) -> None:
        """Atualiza a UI com o resultado da auditoria avancada."""
        self._finish_visual_progress("audit", interrupted=False)
        stamp = datetime.now().strftime("%H:%M:%S")
        self.last_audit_report = report
        self.audit_page.populate_results(report, stamp)
        self._register_executed_scan("Auditoria avancada de seguranca")
        issues_count = sum(1 for finding in report.findings if finding.score > 0)
        self.statusBar().showMessage(
            f"Auditoria avancada finalizada | score={report.total_score} | achados={issues_count} | status={report.overall_status.value}"
        )
        self._save_history_entry(
            HistoryRecordInput(
                scan_type="Auditoria avancada de seguranca",
                analyzed_count=len(report.findings),
                suspicious_count=issues_count,
                summary=f"Score total={report.total_score} | status={report.overall_status.value}",
            )
        )

    def _resolve_audit_problems(self) -> None:
        """Aplica resolucao em lote para todos os achados inseguros suportados."""
        if self._has_active_background_task():
            QMessageBox.information(self, "Operacao em andamento", "Aguarde o termino da operacao atual antes de resolver problemas.")
            return

        if self.last_audit_report is None:
            QMessageBox.information(self, "Sem dados", "Execute a Auditoria Avancada antes de resolver problemas.")
            return

        findings_to_fix = [
            finding
            for finding in self.last_audit_report.findings
            if finding.status != AuditStatus.SAFE
        ]
        if not findings_to_fix:
            QMessageBox.information(self, "Sem problemas", "Nao ha problemas para resolver nesta auditoria.")
            return

        auto_fixable = [finding for finding in findings_to_fix if finding.auto_resolvable and finding.resolver_key]
        if not auto_fixable:
            QMessageBox.information(
                self,
                "Resolucao manual necessaria",
                "Foram encontrados problemas, mas nenhum deles possui correcao automatica segura. "
                "Use as recomendacoes de cada item.",
            )
            return

        policy = build_action_policy(
            action_id="audit_resolve_batch",
            title="Aplicar correcoes automaticas da auditoria",
            description="O SentinelaPC vai tentar aplicar apenas correcoes consideradas seguras e suportadas para os achados atuais da auditoria.",
            severity=ActionSeverity.CRITICAL,
            confirm_label="Aplicar correcoes",
            requires_admin=any(finding.auto_resolvable for finding in auto_fixable),
            admin_reason="Algumas correcoes alteram configuracoes do Windows e exigem elevacao administrativa para serem aplicadas de forma segura.",
            detail_lines=(
                f"Problemas detectados: {len(findings_to_fix)}",
                f"Problemas auto-resoluveis: {len(auto_fixable)}",
                "As correcoes nao removem manualmente itens sem suporte automatico.",
            ),
        )
        correlation_id = self._confirm_sensitive_action(
            policy,
            target_summary=(
                f"Achados corrigiveis agora: {len(auto_fixable)} | "
                f"acao manual restante: {len(findings_to_fix) - len(auto_fixable)}"
            ),
        )
        if correlation_id is None:
            return

        if not self._ensure_admin_permission(
            policy,
            target_summary="Correcoes automaticas da auditoria avancada",
            correlation_id=correlation_id,
        ):
            return

        resolved_count = 0
        failed_count = 0
        permission_failed_count = 0
        restart_required = False
        detail_lines: list[str] = []
        for finding in auto_fixable:
            result = self.audit_service.resolve_finding(finding)
            prefix = "[OK]" if result.applied else "[ERRO]"
            detail_lines.append(f"{prefix} {finding.problem_name}: {result.message}")
            if result.applied:
                resolved_count += 1
            else:
                failed_count += 1
                details_text = " ".join(result.details).lower()
                if "administrador" in result.message.lower() or "administrador" in details_text:
                    permission_failed_count += 1
            restart_required = restart_required or result.requires_restart

        manual_count = len(findings_to_fix) - len(auto_fixable)
        summary = (
            f"Resolvidos automaticamente: {resolved_count}\n"
            f"Falhas na auto-correcao: {failed_count}\n"
            f"Exigem acao manual: {manual_count}"
        )
        if permission_failed_count > 0:
            summary += (
                f"\nFalhas por permissao (admin): {permission_failed_count}"
                "\nExecute o SentinelaPC como administrador e tente novamente."
            )
        if restart_required:
            summary += "\n\nAlgumas alteracoes podem exigir reinicializacao do Windows."

        message = summary
        if detail_lines:
            message += "\n\nDetalhes:\n" + "\n".join(detail_lines)

        QMessageBox.information(self, "Resolucao em lote concluida", message)
        self.statusBar().showMessage("Resolucao em lote concluida. Reexecute a Auditoria Avancada para validar o resultado.")

        final_status = "succeeded"
        if failed_count > 0 and resolved_count == 0:
            final_status = "failed"
        elif failed_count > 0 or manual_count > 0:
            final_status = "partial"

        self._record_action_event(
            policy,
            f"auto_fixable={len(auto_fixable)}",
            "approved",
            final_status,
            (
                f"Resolvidos={resolved_count} | falhas={failed_count} | "
                f"manuais={manual_count} | admin_falhas={permission_failed_count} | reinicio={restart_required}"
            ),
            correlation_id,
        )

    def _handle_audit_failed(self, error_message: str) -> None:
        """Registra falha inesperada da auditoria avancada."""
        self._finish_visual_progress("audit", interrupted=True)
        self.last_audit_report = None
        self.statusBar().showMessage("Falha na auditoria avancada de seguranca.")
        log_error(self.context.logger, "Falha inesperada na auditoria avancada.", RuntimeError(error_message))

    def _export_audit_report(self, report_format: str) -> None:
        """Exporta o ultimo relatorio de auditoria para TXT ou JSON."""
        if self.last_audit_report is None:
            QMessageBox.information(self, "Sem dados", "Execute a Auditoria Avancada antes de exportar.")
            return

        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        if report_format == "txt":
            file_path = self.context.paths.reports_dir / f"sentinelapc-auditoria-{timestamp}.txt"
            self.audit_service.export_to_txt(self.last_audit_report, file_path)
        else:
            file_path = self.context.paths.reports_dir / f"sentinelapc-auditoria-{timestamp}.json"
            self.audit_service.export_to_json(self.last_audit_report, file_path)
        self.statusBar().showMessage(f"Relatorio de auditoria exportado: {file_path.name}")

    def _is_running_as_admin(self) -> bool:
        """Retorna True quando o processo atual possui privilegios elevados no Windows."""
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False

    def _relaunch_as_admin(self) -> bool:
        """Solicita elevacao UAC e reinicia o app no mesmo modo de execucao atual."""
        try:
            if getattr(sys, "frozen", False):
                executable = sys.executable
                params = subprocess.list2cmdline(sys.argv[1:])
            else:
                executable = sys.executable
                script_path = str(Path(sys.argv[0]).resolve())
                params = subprocess.list2cmdline([script_path, *sys.argv[1:]])

            result = ctypes.windll.shell32.ShellExecuteW(None, "runas", executable, params, None, 1)
            return result > 32
        except Exception as exc:
            log_warning(self.context.logger, f"Falha ao solicitar elevacao UAC: {exc}")
            return False

    def _confirm_sensitive_action(self, policy: ActionPolicy, *, target_summary: str) -> str | None:
        """Exibe confirmacao padronizada e registra a decisao do operador."""
        correlation_id = self._new_action_correlation_id(policy.action_id)
        dialog = ConfirmActionDialog(policy, target_summary=target_summary, parent=self)
        if dialog.exec() != dialog.DialogCode.Accepted:
            self._record_action_event(
                policy,
                target_summary,
                "cancelled",
                "skipped",
                "Usuario cancelou a confirmacao antes da execucao.",
                correlation_id,
            )
            return None

        self._record_action_event(
            policy,
            target_summary,
            "approved",
            "pending",
            "Confirmacao concedida na interface.",
            correlation_id,
        )
        return correlation_id

    def _ensure_admin_permission(
        self,
        policy: ActionPolicy,
        *,
        target_summary: str,
        correlation_id: str,
    ) -> bool:
        """Solicita elevacao quando a politica exigir privilegios administrativos."""
        if not policy.requires_admin or self._is_running_as_admin():
            return True

        dialog = AdminPermissionDialog(policy, target_summary=target_summary, parent=self)
        if dialog.exec() != dialog.DialogCode.Accepted or dialog.choice != "relaunch":
            self._record_action_event(
                policy,
                target_summary,
                "cancelled",
                "skipped",
                "Usuario optou por nao reiniciar o aplicativo com privilegios elevados.",
                correlation_id,
            )
            return False

        if self._relaunch_as_admin():
            self._record_action_event(
                policy,
                target_summary,
                "relaunch",
                "handoff",
                "Aplicativo reiniciado para concluir a acao com privilegios elevados.",
                correlation_id,
            )
            QApplication.quit()
            return False

        self._record_action_event(
            policy,
            target_summary,
            "relaunch",
            "failed",
            "Falha ao solicitar elevacao UAC automaticamente.",
            correlation_id,
        )
        QMessageBox.warning(
            self,
            "Falha ao elevar privilegios",
            "Nao foi possivel solicitar elevacao UAC automaticamente. Abra o aplicativo manualmente como administrador.",
        )
        return False

    def _record_action_event(
        self,
        policy: ActionPolicy,
        target_summary: str,
        decision: str,
        status: str,
        details: str,
        correlation_id: str,
    ) -> None:
        """Registra no banco e no log tecnico um evento de acao sensivel."""
        try:
            self.action_event_repository.save_event(
                ActionEventRecordInput(
                    action_id=policy.action_id,
                    action_title=policy.title,
                    severity=policy.severity.value,
                    target_summary=target_summary,
                    requires_admin=policy.requires_admin,
                    decision=decision,
                    status=status,
                    details=details,
                    correlation_id=correlation_id,
                )
            )
        except Exception as error:
            log_error(self.context.logger, "Falha ao registrar evento de acao sensivel.", error)
            return

        log_info(
            self.context.logger,
            (
                "Evento de acao registrado | "
                f"action_id={policy.action_id} | severity={policy.severity.value} | decision={decision} | "
                f"status={status} | correlation_id={correlation_id} | target={target_summary}"
            ),
        )

    def _new_action_correlation_id(self, action_id: str) -> str:
        """Gera um identificador curto para correlacionar confirmacao e resultado."""
        return f"{action_id}-{uuid4().hex[:10]}"

    def _resolve_connected_email_provider(self) -> EmailProvider | None:
        """Resolve o provedor atualmente conectado a partir do status persistido."""
        try:
            gmail_status = self.email_account_service.get_status(EmailProvider.GMAIL)
            if gmail_status.connected:
                return EmailProvider.GMAIL

            outlook_status = self.email_account_service.get_status(EmailProvider.OUTLOOK)
            if outlook_status.connected:
                return EmailProvider.OUTLOOK
        except Exception:
            return None
        return None

    def _build_email_sources_summary(self, sources: list[Path], origin_label: str) -> str:
        """Resume de forma legivel as origens escolhidas para analise local de e-mails."""
        if not sources:
            return f"Origem selecionada: {origin_label}"

        if len(sources) == 1:
            return f"Origem selecionada: {sources[0]}"

        preview = [str(path) for path in sources[:3]]
        lines = [f"Origem: {origin_label}", *preview]
        if len(sources) > 3:
            lines.append(f"... e mais {len(sources) - 3} item(ns).")
        return "\n".join(lines)

    def _start_diagnostics(self) -> None:
        """Executa o diagnostico de saude do PC em background."""
        if self._has_active_background_task():
            self._append_to_page("diagnostics", ["[Diagnostico] Ja existe uma operacao em andamento."])
            log_warning(self.context.logger, "Tentativa de iniciar diagnostico com outra operacao ativa.")
            return

        self._prepare_operation_page(
            "diagnostics",
            [
                "[Diagnostico] Diagnostico de saude do PC iniciado.",
                "[Diagnostico] Coletando CPU, memoria, disco, inicializacao e sinais simples de lentidao...",
            ],
        )
        self.diagnostics_page.update_summary(0, 0, datetime.now().strftime("%H:%M:%S"))
        self.statusBar().showMessage("Executando diagnostico do sistema...")
        self._set_busy_actions(False)
        self._is_diagnostics_paused = False
        self._start_visual_progress("diagnostics", "Diagnostico do sistema")
        self._set_diagnostics_control_actions(True)
        log_info(self.context.logger, "Diagnostico do sistema iniciado pela interface.")

        self.diagnostics_thread = QThread(self)
        self.diagnostics_worker = DiagnosticsWorker(
            self.diagnostics_service,
            self.last_startup_scan_report,
            self.last_file_scan_report,
            self.last_process_scan_report,
        )
        self.diagnostics_worker.moveToThread(self.diagnostics_thread)
        self._connect_background_worker(
            thread=self.diagnostics_thread,
            worker=self.diagnostics_worker,
            success_handler=self._handle_diagnostics_finished,
            failure_handler=self._handle_diagnostics_failed,
            cleanup_handler=self._cleanup_diagnostics_thread,
        )
        self.diagnostics_thread.start()

    def _toggle_diagnostics_pause(self) -> None:
        """Pausa ou retoma o diagnostico do sistema em andamento."""
        if self.diagnostics_worker is None or self.diagnostics_thread is None:
            self._append_to_page("diagnostics", ["[Diagnostico] Nenhum diagnostico esta em andamento."])
            return

        self._is_diagnostics_paused = self.diagnostics_worker.toggle_pause()
        self._set_visual_progress_paused(self._is_diagnostics_paused)
        if self._is_diagnostics_paused:
            message = "[Diagnostico] Pausa solicitada. O diagnostico sera pausado no proximo ponto seguro."
            self.statusBar().showMessage("Pausa solicitada para o diagnostico.")
        else:
            message = "[Diagnostico] Retomada solicitada. O diagnostico continuara de onde parou."
            self.statusBar().showMessage("Diagnostico retomado.")

        self._append_to_page("diagnostics", [message])

    def _stop_diagnostics(self) -> None:
        """Solicita interrupcao cooperativa do diagnostico do sistema."""
        if self.diagnostics_worker is None or self.diagnostics_thread is None:
            self._append_to_page("diagnostics", ["[Diagnostico] Nenhum diagnostico esta em andamento."])
            return

        confirmation = QMessageBox.question(
            self,
            "Parar diagnostico",
            "Deseja interromper o diagnostico atual e manter apenas o resultado parcial?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if confirmation != QMessageBox.StandardButton.Yes:
            return

        self.diagnostics_worker.request_cancel()
        self._is_diagnostics_paused = False
        self._set_visual_progress_paused(False)
        self._append_to_page("diagnostics", ["[Diagnostico] Interrupcao solicitada. Encerrando no proximo ponto seguro..."])
        self.statusBar().showMessage("Interrupcao solicitada para o diagnostico.")

    def _append_scan_progress(self, message: str) -> None:
        """Encaminha o progresso do worker para a pagina ativa e para a barra de status."""
        page = self._get_operation_page(self._active_operation_page_id)
        if page is not None:
            page.append_lines([message])
        self._touch_visual_progress(message)
        self.statusBar().showMessage(message)

    def _update_file_scan_progress_summary(self, analyzed: int, suspicious: int) -> None:
        """Atualiza os cards da pagina de arquivos em tempo real durante a varredura."""
        self._current_file_scan_analyzed = analyzed
        self._current_file_scan_suspicious = suspicious
        self.files_page.update_summary(analyzed, suspicious, datetime.now().strftime("%H:%M:%S"))

    def _handle_scan_finished(self, report: FileScanReport) -> None:
        """Apresenta o resultado final da verificacao de arquivos na tela dedicada."""
        self._finish_visual_progress("files", interrupted=report.interrupted)
        summary_lines = [
            f"[Scanner] {report.scan_label} interrompida pelo usuario."
            if report.interrupted
            else f"[Scanner] {report.scan_label} concluida.",
            f"[Scanner] Total de arquivos verificados: {report.scanned_files}",
            f"[Scanner] Itens suspeitos encontrados: {report.flagged_files}",
        ]
        if report.errors:
            summary_lines.append(f"[Scanner] Ocorreram {len(report.errors)} erros de acesso durante a analise.")

        if report.results:
            summary_lines.append("[Scanner] Lista de itens suspeitos:")
            for result in report.results:
                summary_lines.append(
                    (
                        f"  - {result.path} | tam={result.size} bytes | ext={result.extension} | "
                        f"score={result.heuristic_score} | classe={result.final_classification.value} | "
                        f"risco={result.initial_risk_level} | motivo={result.alert_reason}"
                    )
                )
        else:
            summary_lines.append("[Scanner] Nenhum item suspeito foi encontrado nesta analise.")

        self.files_page.append_lines(summary_lines)
        self.files_page.update_summary(report.scanned_files, report.flagged_files, datetime.now().strftime("%H:%M:%S"))
        self._append_dashboard_activity(summary_lines)
        self.last_file_scan_report = report
        self._register_executed_scan(report.scan_label)
        self.statusBar().showMessage(
            (
                f"{report.scan_label} interrompida | arquivos={report.scanned_files} | suspeitos={report.flagged_files}"
                if report.interrupted
                else f"{report.scan_label} finalizada | arquivos={report.scanned_files} | suspeitos={report.flagged_files}"
            )
        )
        log_info(self.context.logger, f"Resultado entregue para a interface | arquivos={report.scanned_files} | suspeitos={report.flagged_files}")
        self._save_history_entry(
            HistoryRecordInput(
                scan_type=report.scan_label,
                analyzed_count=report.scanned_files,
                suspicious_count=report.flagged_files,
                summary=(
                    f"Pasta analisada: {report.target_directory} | erros={len(report.errors)} | suspeitos={report.flagged_files} | interrompida=sim"
                    if report.interrupted
                    else f"Pasta analisada: {report.target_directory} | erros={len(report.errors)} | suspeitos={report.flagged_files}"
                ),
            )
        )

    def _handle_process_scan_finished(self, report: ProcessScanReport) -> None:
        """Apresenta o resultado final da verificacao de processos na tela dedicada."""
        self._finish_visual_progress("processes", interrupted=report.interrupted)
        summary_lines = [
            "[Processos] Verificacao interrompida pelo usuario." if report.interrupted else "[Processos] Verificacao concluida.",
            f"[Processos] Total de processos avaliados: {report.inspected_processes}",
            f"[Processos] Processos suspeitos encontrados: {report.suspicious_processes}",
        ]
        if report.errors:
            summary_lines.append(f"[Processos] Ocorreram {len(report.errors)} erros de acesso durante a leitura.")

        if report.results:
            summary_lines.append("[Processos] Lista de processos suspeitos:")
            for result in report.results:
                executable_path = result.executable_path or "caminho_indisponivel"
                summary_lines.append(
                    (
                        f"  - {result.name} | PID={result.pid} | exe={executable_path} | "
                        f"CPU={result.cpu_usage_percent:.1f}% | MEM={result.memory_usage_percent:.1f}% | "
                        f"score={result.heuristic_score} | classe={result.final_classification.value} | "
                        f"risco={result.initial_risk_level} | motivo={result.alert_reason}"
                    )
                )
        else:
            summary_lines.append("[Processos] Nenhum processo suspeito foi encontrado nesta verificacao.")

        self.processes_page.append_lines(summary_lines)
        self.processes_page.update_summary(report.inspected_processes, report.suspicious_processes, datetime.now().strftime("%H:%M:%S"))
        self._append_dashboard_activity(summary_lines)
        self.last_process_scan_report = report
        self._register_executed_scan("Verificacao de processos")
        self.statusBar().showMessage(
            (
                f"Verificacao de processos interrompida | processos={report.inspected_processes} | suspeitos={report.suspicious_processes}"
                if report.interrupted
                else f"Verificacao de processos finalizada | processos={report.inspected_processes} | suspeitos={report.suspicious_processes}"
            )
        )
        log_info(self.context.logger, f"Resultado de processos entregue para a interface | processos={report.inspected_processes} | suspeitos={report.suspicious_processes}")
        self._save_history_entry(
            HistoryRecordInput(
                scan_type="Verificacao de processos",
                analyzed_count=report.inspected_processes,
                suspicious_count=report.suspicious_processes,
                summary=f"Processos avaliados: {report.inspected_processes} | erros={len(report.errors)} | suspeitos={report.suspicious_processes}",
            )
        )

    def _handle_startup_scan_finished(self, report: StartupScanReport) -> None:
        """Apresenta o resultado final da verificacao de inicializacao na tela dedicada."""
        self._finish_visual_progress("startup", interrupted=report.interrupted)
        summary_lines = [
            "[Inicializacao] Verificacao interrompida pelo usuario." if report.interrupted else "[Inicializacao] Verificacao concluida.",
            f"[Inicializacao] Total de itens avaliados: {report.inspected_items}",
            f"[Inicializacao] Itens suspeitos encontrados: {report.suspicious_items}",
        ]
        if report.errors:
            summary_lines.append(f"[Inicializacao] Ocorreram {len(report.errors)} erros de leitura durante a verificacao.")

        if report.results:
            summary_lines.append("[Inicializacao] Lista de itens encontrados:")
            for result in report.results:
                summary_lines.append(
                    (
                        f"  - {result.name} | origem={result.origin} | tipo={result.item_type} | "
                        f"score={result.heuristic_score} | classe={result.final_classification.value} | "
                        f"risco={result.risk_level} | comando={result.command} | motivo={result.flag_reason}"
                    )
                )
        else:
            summary_lines.append("[Inicializacao] Nenhum item suspeito de inicializacao foi encontrado.")

        self.startup_page.append_lines(summary_lines)
        self.startup_page.update_summary(report.inspected_items, report.suspicious_items, datetime.now().strftime("%H:%M:%S"))
        self._append_dashboard_activity(summary_lines)
        self.last_startup_scan_report = report
        self._register_executed_scan("Verificacao de inicializacao")
        self.statusBar().showMessage(
            (
                f"Verificacao de inicializacao interrompida | itens={report.inspected_items} | suspeitos={report.suspicious_items}"
                if report.interrupted
                else f"Verificacao de inicializacao finalizada | itens={report.inspected_items} | suspeitos={report.suspicious_items}"
            )
        )
        log_info(self.context.logger, f"Resultado de inicializacao entregue para a interface | itens={report.inspected_items} | suspeitos={report.suspicious_items}")
        self._save_history_entry(
            HistoryRecordInput(
                scan_type="Verificacao de inicializacao",
                analyzed_count=report.inspected_items,
                suspicious_count=report.suspicious_items,
                summary=f"Itens de startup avaliados: {report.inspected_items} | erros={len(report.errors)} | suspeitos={report.suspicious_items}",
            )
        )

    def _handle_diagnostics_finished(self, report: SystemDiagnosticsReport) -> None:
        """Apresenta o diagnostico de saude do sistema na pagina dedicada."""
        self._finish_visual_progress("diagnostics", interrupted=report.interrupted)
        summary_lines = [
            "[Diagnostico] Diagnostico interrompido pelo usuario." if report.interrupted else "[Diagnostico] Diagnostico concluido.",
            f"[Diagnostico] CPU atual: {report.cpu_usage_percent:.1f}%",
            f"[Diagnostico] Memoria atual: {report.memory_usage_percent:.1f}%",
            f"[Diagnostico] Disco em uso: {report.disk_usage_percent:.1f}%",
            f"[Diagnostico] Espaco livre em disco: {report.free_disk_gb:.2f} GB de {report.total_disk_gb:.2f} GB",
            f"[Diagnostico] Itens de startup detectados: {report.startup_items_count}",
        ]
        if report.heavy_processes:
            summary_lines.append("[Diagnostico] Processos mais pesados:")
            for process in report.heavy_processes:
                executable_path = process.executable_path or "caminho_indisponivel"
                summary_lines.append(
                    f"  - {process.name} | PID={process.pid} | CPU={process.cpu_usage_percent:.1f}% | MEM={process.memory_usage_percent:.1f}% | exe={executable_path}"
                )
        if report.startup_programs:
            summary_lines.append("[Diagnostico] Exemplos de programas iniciando com o sistema: " + ", ".join(report.startup_programs))
        if report.slowdown_signals:
            summary_lines.append("[Diagnostico] Possiveis sinais de lentidao:")
            for signal in report.slowdown_signals:
                summary_lines.append(f"  - {signal}")
        if report.path_errors:
            summary_lines.append("[Diagnostico] Erros simples de acesso observados:")
            for error in report.path_errors:
                summary_lines.append(f"  - {error.source} | {error.location} | {error.message}")
        if report.issues:
            summary_lines.append("[Diagnostico] Achados do diagnostico:")
            for issue in report.issues:
                summary_lines.append(f"  - {issue.category} | severidade={issue.severity} | {issue.message}")

        startup_candidates = len(report.startup_report_used.results) if report.startup_report_used is not None else 0
        summary_lines.append(f"[Diagnostico] Achados de saude registrados: {len(report.issues)}")
        summary_lines.append(
            "[Diagnostico] Itens para quarentena disponiveis agora: "
            f"startup={startup_candidates}. "
            "Achados de saude (CPU/disco/erros) nao sao enviados para quarentena."
        )

        self.diagnostics_page.append_lines(summary_lines)
        self.diagnostics_page.update_summary(
            4 + len(report.heavy_processes) + report.startup_items_count,
            startup_candidates,
            datetime.now().strftime("%H:%M:%S"),
        )
        self._append_dashboard_activity(summary_lines)
        self.last_diagnostics_report = report
        if report.startup_report_used is not None:
            # Reaproveita os itens de startup gerados no diagnostico para quarentena sem novo scan.
            self.last_startup_scan_report = report.startup_report_used
        self._register_executed_scan("Diagnostico do sistema")
        self.statusBar().showMessage(
            "Diagnostico do sistema interrompido."
            if report.interrupted
            else "Diagnostico do sistema finalizado com sucesso."
        )
        self._save_history_entry(
            HistoryRecordInput(
                scan_type="Diagnostico do sistema",
                analyzed_count=4 + len(report.heavy_processes) + report.startup_items_count,
                suspicious_count=startup_candidates,
                summary=f"CPU={report.cpu_usage_percent:.1f}% | memoria={report.memory_usage_percent:.1f}% | disco={report.disk_usage_percent:.1f}% | startup={report.startup_items_count}",
            )
        )

    def _handle_browser_scan_finished(self, report: BrowserScanReport) -> None:
        """Apresenta o resultado da analise de navegadores na tela dedicada."""
        self._finish_visual_progress("browsers", interrupted=report.interrupted)
        summary_lines = [
            "[Navegadores] Analise interrompida pelo usuario." if report.interrupted else "[Navegadores] Analise concluida.",
            f"[Navegadores] Total de itens avaliados: {report.inspected_items}",
            f"[Navegadores] Itens suspeitos encontrados: {report.suspicious_items}",
        ]
        if report.errors:
            summary_lines.append(f"[Navegadores] Ocorreram {len(report.errors)} erros de leitura.")

        if report.results:
            summary_lines.append("[Navegadores] Achados relevantes:")
            for result in report.results:
                path_text = str(result.path) if result.path is not None else "caminho_indisponivel"
                summary_lines.append(
                    (
                        f"  - navegador={result.browser} | tipo={result.item_type} | nome={result.name} | "
                        f"score={result.score} | classe={result.classification.value} | caminho={path_text} | "
                        f"motivos={'; '.join(result.reasons)}"
                    )
                )
        else:
            summary_lines.append("[Navegadores] Nenhum item suspeito foi encontrado.")

        self.browsers_page.append_lines(summary_lines)
        self.browsers_page.update_summary(report.inspected_items, report.suspicious_items, datetime.now().strftime("%H:%M:%S"))
        self._append_dashboard_activity(summary_lines)
        self.last_browser_scan_report = report
        self._register_executed_scan("Analise de navegadores")
        self._save_history_entry(
            HistoryRecordInput(
                scan_type="Analise de navegadores",
                analyzed_count=report.inspected_items,
                suspicious_count=report.suspicious_items,
                summary=f"Navegadores avaliados em modo local | erros={len(report.errors)}",
            )
        )

    def _handle_email_scan_finished(self, report: EmailScanReport) -> None:
        """Apresenta o resultado da analise local de e-mails na tela dedicada."""
        self._finish_visual_progress("emails", interrupted=report.interrupted)
        summary_lines = [
            "[E-mails] Analise interrompida pelo usuario." if report.interrupted else "[E-mails] Analise concluida.",
            f"[E-mails] Total de itens avaliados: {report.inspected_items}",
            f"[E-mails] Itens suspeitos encontrados: {report.suspicious_items}",
        ]
        if report.errors:
            summary_lines.append(f"[E-mails] Ocorreram {len(report.errors)} erros de leitura/parse.")

        if report.results:
            summary_lines.append("[E-mails] Achados relevantes:")
            for result in report.results:
                summary_lines.append(
                    (
                        f"  - origem={result.source_label or result.source_file} | assunto={result.subject} | remetente={result.sender} | "
                        f"links={result.links_found} | anexos={result.attachments_found} | "
                        f"score={result.score} | classe={result.classification.value} | motivos={'; '.join(result.reasons)}"
                    )
                )
        else:
            summary_lines.append("[E-mails] Nenhum item suspeito foi encontrado.")

        self.emails_page.append_lines(summary_lines)
        self.emails_page.update_summary(report.inspected_items, report.suspicious_items, datetime.now().strftime("%H:%M:%S"))
        self._append_dashboard_activity(summary_lines)
        self.last_email_scan_report = report
        scan_label = (
            f"Analise online de e-mails ({report.provider})"
            if report.source_kind == "online" and report.provider
            else "Analise de e-mails"
        )
        self._register_executed_scan(scan_label)
        if self._active_email_scan_correlation_id is not None and self._active_email_scan_policy is not None:
            self._record_action_event(
                self._active_email_scan_policy,
                self._active_email_scan_summary or "Analise de e-mails",
                "approved",
                "interrupted" if report.interrupted else "succeeded",
                f"Itens analisados={report.inspected_items} | suspeitos={report.suspicious_items} | erros={len(report.errors)}",
                self._active_email_scan_correlation_id,
            )
            self._active_email_scan_correlation_id = None
            self._active_email_scan_summary = ""
            self._active_email_scan_policy = None
        self._save_history_entry(
            HistoryRecordInput(
                scan_type=scan_label,
                analyzed_count=report.inspected_items,
                suspicious_count=report.suspicious_items,
                summary=(
                    f"E-mails online ({report.provider}) avaliados em modo somente leitura | erros={len(report.errors)}"
                    if report.source_kind == "online" and report.provider
                    else f"E-mails locais avaliados em modo somente leitura | erros={len(report.errors)}"
                ),
            )
        )

    def _handle_scan_failed(self, error_message: str) -> None:
        """Registra falhas inesperadas da verificacao de arquivos."""
        self._finish_visual_progress("files", interrupted=True)
        self._report_background_failure(
            page_id="files",
            display_prefix="[Scanner] Falha inesperada durante a verificacao",
            status_message=f"Falha na {self._current_file_scan_display_name.lower()}.",
            log_message=f"Falha inesperada na {self._current_file_scan_history_label.lower()}.",
            error_message=error_message,
            report_attr_name="last_file_scan_report",
        )

    def _handle_process_scan_failed(self, error_message: str) -> None:
        """Registra falhas inesperadas da verificacao de processos."""
        self._finish_visual_progress("processes", interrupted=True)
        self._report_background_failure(
            page_id="processes",
            display_prefix="[Processos] Falha inesperada durante a verificacao",
            status_message="Falha na verificacao de processos.",
            log_message="Falha inesperada na verificacao de processos.",
            error_message=error_message,
        )

    def _handle_startup_scan_failed(self, error_message: str) -> None:
        """Registra falhas inesperadas da verificacao de inicializacao."""
        self._finish_visual_progress("startup", interrupted=True)
        self._report_background_failure(
            page_id="startup",
            display_prefix="[Inicializacao] Falha inesperada durante a verificacao",
            status_message="Falha na verificacao de inicializacao.",
            log_message="Falha inesperada na verificacao de inicializacao.",
            error_message=error_message,
        )

    def _handle_diagnostics_failed(self, error_message: str) -> None:
        """Registra falhas inesperadas do diagnostico do sistema."""
        self._finish_visual_progress("diagnostics", interrupted=True)
        self._report_background_failure(
            page_id="diagnostics",
            display_prefix="[Diagnostico] Falha inesperada durante o diagnostico",
            status_message="Falha no diagnostico do sistema.",
            log_message="Falha inesperada no diagnostico do sistema.",
            error_message=error_message,
        )

    def _handle_browser_scan_failed(self, error_message: str) -> None:
        """Registra falhas inesperadas da analise de navegadores."""
        self._finish_visual_progress("browsers", interrupted=True)
        self._report_background_failure(
            page_id="browsers",
            display_prefix="[Navegadores] Falha inesperada durante a analise",
            status_message="Falha na analise de navegadores.",
            log_message="Falha inesperada na analise de navegadores.",
            error_message=error_message,
            report_attr_name="last_browser_scan_report",
        )

    def _handle_email_scan_failed(self, error_message: str) -> None:
        """Registra falhas inesperadas da analise de e-mails."""
        self._finish_visual_progress("emails", interrupted=True)
        if self._active_email_scan_correlation_id is not None and self._active_email_scan_policy is not None:
            self._record_action_event(
                self._active_email_scan_policy,
                self._active_email_scan_summary or "Analise de e-mails",
                "approved",
                "failed",
                error_message,
                self._active_email_scan_correlation_id,
            )
            self._active_email_scan_correlation_id = None
            self._active_email_scan_summary = ""
            self._active_email_scan_policy = None
        self._report_background_failure(
            page_id="emails",
            display_prefix="[E-mails] Falha inesperada durante a analise",
            status_message="Falha na analise de e-mails.",
            log_message="Falha inesperada na analise de e-mails.",
            error_message=error_message,
            report_attr_name="last_email_scan_report",
        )

    def _cleanup_scan_thread(self) -> None:
        """Libera recursos usados pela verificacao de arquivos."""
        self._is_file_scan_paused = False
        self._cleanup_worker_resources("scan_worker", "scan_thread")
        self._set_file_scan_control_actions(False)
        self._set_busy_actions(True)

    def _cleanup_process_thread(self) -> None:
        """Libera recursos usados pela verificacao de processos."""
        self._is_process_scan_paused = False
        self._cleanup_worker_resources("process_worker", "process_thread")
        self._set_process_scan_control_actions(False)
        self._set_busy_actions(True)

    def _cleanup_startup_thread(self) -> None:
        """Libera recursos usados pela verificacao de inicializacao."""
        self._is_startup_scan_paused = False
        self._cleanup_worker_resources("startup_worker", "startup_thread")
        self._set_startup_scan_control_actions(False)
        self._set_busy_actions(True)

    def _cleanup_diagnostics_thread(self) -> None:
        """Libera recursos usados pelo diagnostico do sistema."""
        self._is_diagnostics_paused = False
        self._cleanup_worker_resources("diagnostics_worker", "diagnostics_thread")
        self._set_diagnostics_control_actions(False)
        self._set_busy_actions(True)

    def _cleanup_browser_thread(self) -> None:
        """Libera recursos usados pela analise de navegadores."""
        self._is_browser_scan_paused = False
        self._cleanup_worker_resources("browser_worker", "browser_thread")
        self._set_browser_scan_control_actions(False)
        self._set_busy_actions(True)

    def _cleanup_email_thread(self) -> None:
        """Libera recursos usados pela analise de e-mails."""
        self._is_email_scan_paused = False
        self._cleanup_worker_resources("email_worker", "email_thread")
        self._set_email_scan_control_actions(False)
        self._set_busy_actions(True)

    def _cleanup_audit_thread(self) -> None:
        """Libera recursos usados pela auditoria avancada."""
        self._is_audit_running = False
        self._cleanup_worker_resources("audit_worker", "audit_thread")
        self._set_audit_control_actions(False)
        self._set_busy_actions(True)

    def _generate_session_report(self) -> None:
        """Gera relatorios TXT e HTML usando os dados acumulados na sessao."""
        session_data = SessionReportData(
            generated_at=datetime.now(),
            executed_scan_types=list(self.executed_scan_types),
            file_report=self.last_file_scan_report,
            process_report=self.last_process_scan_report,
            startup_report=self.last_startup_scan_report,
            diagnostics_report=self.last_diagnostics_report,
            quarantined_items=list(self.session_quarantine_items),
        )

        if (
            session_data.file_report is None
            and session_data.process_report is None
            and session_data.startup_report is None
            and session_data.diagnostics_report is None
        ):
            QMessageBox.information(self, "Sem dados na sessao", "Execute pelo menos um scan nesta sessao antes de gerar o relatorio.")
            return

        try:
            generated_files = self.report_service.generate_session_report(session_data)
        except Exception as error:
            log_error(self.context.logger, "Falha ao gerar relatorios da sessao.", error)
            QMessageBox.critical(self, "Falha ao gerar relatorio", f"Nao foi possivel gerar os arquivos de relatorio: {error}")
            return

        created_at = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
        self.reports_page.add_report(created_at, generated_files.txt_file, generated_files.html_file)
        report_lines = [
            "[Relatorio] Relatorios da sessao gerados com sucesso.",
            f"[Relatorio] TXT: {generated_files.txt_file}",
            f"[Relatorio] HTML: {generated_files.html_file}",
        ]
        self._append_dashboard_activity(report_lines)
        self.statusBar().showMessage("Relatorios TXT e HTML gerados com sucesso.")
        self._save_history_entry(
            HistoryRecordInput(
                scan_type="Relatorio da sessao",
                analyzed_count=self.report_service.count_total_analyzed(session_data),
                suspicious_count=self.report_service.count_total_suspicious(session_data),
                summary="Relatorio consolidado da sessao gerado com base nos dados atuais da interface.",
                report_path=f"TXT: {generated_files.txt_file} | HTML: {generated_files.html_file}",
            )
        )
        self._switch_page("reports")

    def _open_quarantine_selection(self) -> None:
        """Permite isolar manualmente um arquivo suspeito do ultimo scan de arquivos."""
        if self._has_active_background_task():
            self._append_to_page("files", ["[Quarentena] Aguarde o termino da operacao atual para mover arquivos."])
            return

        suspicious_files = list(self.last_file_scan_report.results) if self.last_file_scan_report else []
        if not suspicious_files:
            QMessageBox.information(
                self,
                "Nenhum arquivo disponivel",
                (
                    "Nao ha arquivos suspeitos disponiveis para quarentena agora.\n\n"
                    "Use 'Verificar arquivos suspeitos' para gerar itens de arquivo, ou use os botoes de quarentena "
                    "de Processos/Inicializacao quando os suspeitos vierem desses modulos."
                ),
            )
            return

        dialog = QuarantineSelectionDialog(suspicious_files, self)

        if dialog.exec() != dialog.DialogCode.Accepted:
            self._append_to_page("files", ["[Quarentena] Operacao cancelada antes da confirmacao final."])
            return

        selected_results = dialog.selected_results
        if not selected_results:
            self._append_to_page("files", ["[Quarentena] Nenhum arquivo selecionado para envio."])
            return

        if len(selected_results) > 1:
            self._quarantine_all_results(selected_results, dialog.reason)
            return

        selected_result = selected_results[0]
        policy = build_action_policy(
            action_id="quarantine_file_single",
            title="Enviar arquivo para quarentena",
            description="O arquivo sera movido para uma area isolada e deixara de ficar disponivel no local original.",
            severity=ActionSeverity.HIGH,
            confirm_label="Enviar para quarentena",
            detail_lines=(
                f"Risco identificado: {selected_result.initial_risk_level.value}",
                f"Motivo registrado: {dialog.reason or 'Nao informado'}",
            ),
            success_message="Arquivo movido para quarentena com sucesso.",
        )
        correlation_id = self._confirm_sensitive_action(
            policy,
            target_summary=f"Arquivo: {selected_result.path}",
        )
        if correlation_id is None:
            self._append_to_page("files", ["[Quarentena] Confirmacao negada pelo usuario. Nenhum arquivo foi movido."])
            return

        try:
            quarantined_item = self.quarantine_service.quarantine_file(
                selected_result.path,
                dialog.reason,
                selected_result.initial_risk_level,
                file_hash=selected_result.sha256,
                user_confirmed=True,
            )
        except FileNotFoundError:
            self._record_action_event(policy, str(selected_result.path), "approved", "failed", "Arquivo nao encontrado no momento da quarentena.", correlation_id)
            QMessageBox.warning(self, "Arquivo indisponivel", "O arquivo selecionado nao foi encontrado. Execute uma nova verificacao antes de tentar novamente.")
            return
        except PermissionError:
            self._record_action_event(policy, str(selected_result.path), "approved", "failed", "Permissao negada pelo Windows ao mover arquivo para quarentena.", correlation_id)
            QMessageBox.critical(self, "Permissao negada", "O Windows negou a movimentacao do arquivo para a quarentena.")
            return
        except Exception as error:
            self._record_action_event(policy, str(selected_result.path), "approved", "failed", f"Erro inesperado: {error}", correlation_id)
            log_error(self.context.logger, "Falha inesperada ao mover arquivo para quarentena.", error)
            QMessageBox.critical(self, "Falha na quarentena", f"Nao foi possivel concluir a quarentena: {error}")
            return

        self._record_action_event(policy, str(selected_result.path), "approved", "succeeded", f"Arquivo enviado para {quarantined_item.quarantined_path}", correlation_id)

        if self.last_file_scan_report is not None:
            self.last_file_scan_report = FileScanReport(
                target_directory=self.last_file_scan_report.target_directory,
                scanned_files=self.last_file_scan_report.scanned_files,
                flagged_files=max(0, self.last_file_scan_report.flagged_files - 1),
                interrupted=self.last_file_scan_report.interrupted,
                scan_label=self.last_file_scan_report.scan_label,
                results=[result for result in self.last_file_scan_report.results if result.path != selected_result.path],
                errors=list(self.last_file_scan_report.errors),
            )
            self.files_page.update_summary(
                self.last_file_scan_report.scanned_files,
                self.last_file_scan_report.flagged_files,
                datetime.now().strftime("%H:%M:%S"),
            )

        lines = [
            f"[Quarentena] Arquivo movido com sucesso: {quarantined_item.original_name}",
            f"[Quarentena] Destino controlado: {quarantined_item.quarantined_path}",
            f"[Quarentena] Motivo registrado: {quarantined_item.reason}",
        ]
        self.session_quarantine_items.append(quarantined_item)
        self._append_to_page("files", lines)
        self._refresh_quarantine_page()
        self._switch_page("quarantine")
        self.statusBar().showMessage("Arquivo movido para quarentena com sucesso.")

    def _quarantine_all_results(self, suspicious_files: list, reason: str) -> None:
        """Move todos os arquivos suspeitos recebidos para quarentena em uma unica operacao."""
        if not suspicious_files:
            QMessageBox.information(self, "Sem itens", "Nao ha arquivos suspeitos para mover para quarentena.")
            return

        policy = build_action_policy(
            action_id="quarantine_file_batch",
            title="Enviar arquivos para quarentena",
            description="Todos os arquivos selecionados serao movidos para a area isolada do SentinelaPC.",
            severity=ActionSeverity.CRITICAL,
            confirm_label="Enviar arquivos",
            detail_lines=(
                f"Total de arquivos selecionados: {len(suspicious_files)}",
                f"Motivo aplicado ao lote: {reason or 'Nao informado'}",
            ),
        )
        correlation_id = self._confirm_sensitive_action(
            policy,
            target_summary=f"Quantidade de arquivos: {len(suspicious_files)}",
        )
        if correlation_id is None:
            self._append_to_page("files", ["[Quarentena] Quarentena em lote cancelada pelo usuario."])
            return

        moved_items = []
        failed_messages = []
        moved_paths: set[Path] = set()

        for result in suspicious_files:
            try:
                quarantined_item = self.quarantine_service.quarantine_file(
                    result.path,
                    reason,
                    result.initial_risk_level,
                    file_hash=result.sha256,
                    user_confirmed=True,
                )
            except FileNotFoundError:
                failed_messages.append(f"{result.path} | arquivo nao encontrado.")
                continue
            except PermissionError:
                failed_messages.append(f"{result.path} | permissao negada pelo Windows.")
                continue
            except Exception as error:
                log_error(self.context.logger, "Falha inesperada ao mover arquivo em lote para quarentena.", error)
                failed_messages.append(f"{result.path} | erro: {error}")
                continue

            moved_items.append(quarantined_item)
            moved_paths.add(result.path)

        if self.last_file_scan_report is not None and moved_paths:
            remaining_results = [result for result in self.last_file_scan_report.results if result.path not in moved_paths]
            self.last_file_scan_report = FileScanReport(
                target_directory=self.last_file_scan_report.target_directory,
                scanned_files=self.last_file_scan_report.scanned_files,
                flagged_files=len(remaining_results),
                interrupted=self.last_file_scan_report.interrupted,
                scan_label=self.last_file_scan_report.scan_label,
                results=remaining_results,
                errors=list(self.last_file_scan_report.errors),
            )
            self.files_page.update_summary(
                self.last_file_scan_report.scanned_files,
                self.last_file_scan_report.flagged_files,
                datetime.now().strftime("%H:%M:%S"),
            )

        if moved_items:
            self.session_quarantine_items.extend(moved_items)

        self._record_action_event(
            policy,
            f"arquivos={len(suspicious_files)}",
            "approved",
            "succeeded" if moved_items else "failed",
            f"Movidos={len(moved_items)} | falhas={len(failed_messages)}",
            correlation_id,
        )

        lines = [
            "[Quarentena] Operacao em lote finalizada.",
            f"[Quarentena] Arquivos movidos com sucesso: {len(moved_items)}",
            f"[Quarentena] Arquivos com falha: {len(failed_messages)}",
        ]

        if failed_messages:
            lines.append("[Quarentena] Falhas durante a operacao em lote:")
            for message in failed_messages[:10]:
                lines.append(f"  - {message}")
            if len(failed_messages) > 10:
                lines.append(f"  - ... e mais {len(failed_messages) - 10} falha(s).")

        self._append_to_page("files", lines)
        self._refresh_quarantine_page()

        if moved_items:
            self._switch_page("quarantine")
            self.statusBar().showMessage(
                f"Quarentena em lote concluida: {len(moved_items)} movido(s), {len(failed_messages)} falha(s)."
            )
            return

        self.statusBar().showMessage("Nenhum arquivo foi movido para quarentena na operacao em lote.")

    def _open_process_quarantine_selection(self) -> None:
        """Permite mover executaveis de processos suspeitos para quarentena."""
        if self._has_active_background_task():
            self._append_to_page("processes", ["[Quarentena] Aguarde o termino da operacao atual para mover arquivos."])
            return

        suspicious_processes = list(self.last_process_scan_report.results) if self.last_process_scan_report else []
        if not suspicious_processes:
            QMessageBox.information(
                self,
                "Nenhum processo disponivel",
                (
                    "Nao ha lista de processos suspeitos pronta para quarentena neste momento.\n\n"
                    "O diagnostico mostra saude do sistema e processos pesados, mas a lista quarentenavel "
                    "de processos vem do modulo 'Verificar processos'."
                ),
            )
            return

        dialog = ProcessQuarantineSelectionDialog(suspicious_processes, self)
        if dialog.exec() != dialog.DialogCode.Accepted:
            self._append_to_page("processes", ["[Quarentena] Operacao cancelada antes da confirmacao final."])
            return

        selected_results = dialog.selected_results
        if not selected_results:
            self._append_to_page("processes", ["[Quarentena] Nenhum executavel valido foi selecionado."])
            return

        if len(selected_results) > 1:
            self._quarantine_all_process_results(selected_results, dialog.reason)
            return

        if selected_results[0].executable_path is None:
            self._append_to_page("processes", ["[Quarentena] Nenhum executavel valido foi selecionado."])
            return

        selected_result = selected_results[0]
        policy = build_action_policy(
            action_id="quarantine_process_single",
            title="Isolar executavel de processo",
            description="O arquivo executavel associado ao processo selecionado sera movido para a area de quarentena.",
            severity=ActionSeverity.CRITICAL,
            confirm_label="Isolar executavel",
            detail_lines=(
                f"Processo: {selected_result.name} (PID {selected_result.pid})",
                f"Risco identificado: {selected_result.initial_risk_level.value}",
            ),
        )
        correlation_id = self._confirm_sensitive_action(
            policy,
            target_summary=f"Executavel: {selected_result.executable_path}",
        )
        if correlation_id is None:
            self._append_to_page("processes", ["[Quarentena] Confirmacao negada pelo usuario."])
            return

        try:
            quarantined_item = self.quarantine_service.quarantine_file(
                selected_result.executable_path,
                dialog.reason,
                selected_result.initial_risk_level,
                user_confirmed=True,
            )
        except FileNotFoundError:
            self._record_action_event(policy, str(selected_result.executable_path), "approved", "failed", "Executavel nao encontrado.", correlation_id)
            QMessageBox.warning(self, "Arquivo indisponivel", "O executavel selecionado nao foi encontrado.")
            return
        except PermissionError:
            self._record_action_event(policy, str(selected_result.executable_path), "approved", "failed", "Permissao negada pelo Windows.", correlation_id)
            QMessageBox.critical(self, "Permissao negada", "O Windows negou a movimentacao do arquivo para a quarentena.")
            return
        except Exception as error:
            self._record_action_event(policy, str(selected_result.executable_path), "approved", "failed", f"Erro inesperado: {error}", correlation_id)
            log_error(self.context.logger, "Falha inesperada ao mover executavel de processo para quarentena.", error)
            QMessageBox.critical(self, "Falha na quarentena", f"Nao foi possivel concluir a quarentena: {error}")
            return

        self._record_action_event(policy, str(selected_result.executable_path), "approved", "succeeded", f"Executavel enviado para {quarantined_item.quarantined_path}", correlation_id)

        self.session_quarantine_items.append(quarantined_item)
        self._append_to_page(
            "processes",
            [
                f"[Quarentena] Executavel movido com sucesso: {quarantined_item.original_name}",
                f"[Quarentena] Destino controlado: {quarantined_item.quarantined_path}",
            ],
        )
        self._refresh_quarantine_page()
        self._switch_page("quarantine")
        self.statusBar().showMessage("Executavel de processo movido para quarentena com sucesso.")

    def _quarantine_all_process_results(self, suspicious_processes: list, reason: str) -> None:
        """Move os executaveis de processos suspeitos para quarentena em lote."""
        candidates = [result for result in suspicious_processes if getattr(result, "executable_path", None) is not None]
        if not candidates:
            QMessageBox.information(self, "Sem itens", "Nao ha executaveis de processos disponiveis para mover.")
            return

        policy = build_action_policy(
            action_id="quarantine_process_batch",
            title="Isolar executaveis de processos",
            description="Todos os executaveis selecionados serao movidos para a area de quarentena do aplicativo.",
            severity=ActionSeverity.CRITICAL,
            confirm_label="Isolar executaveis",
            detail_lines=(
                f"Total de executaveis selecionados: {len(candidates)}",
                f"Motivo aplicado ao lote: {reason or 'Nao informado'}",
            ),
        )
        correlation_id = self._confirm_sensitive_action(
            policy,
            target_summary=f"Executaveis selecionados: {len(candidates)}",
        )
        if correlation_id is None:
            self._append_to_page("processes", ["[Quarentena] Quarentena em lote de processos cancelada pelo usuario."])
            return

        moved_items = []
        failed_messages = []
        for result in candidates:
            try:
                quarantined_item = self.quarantine_service.quarantine_file(
                    result.executable_path,
                    reason,
                    result.initial_risk_level,
                    user_confirmed=True,
                )
            except FileNotFoundError:
                failed_messages.append(f"{result.executable_path} | arquivo nao encontrado.")
                continue
            except PermissionError:
                failed_messages.append(f"{result.executable_path} | permissao negada pelo Windows.")
                continue
            except Exception as error:
                log_error(self.context.logger, "Falha inesperada ao mover executavel de processo em lote para quarentena.", error)
                failed_messages.append(f"{result.executable_path} | erro: {error}")
                continue

            moved_items.append(quarantined_item)

        if moved_items:
            self.session_quarantine_items.extend(moved_items)

        self._record_action_event(
            policy,
            f"executaveis={len(candidates)}",
            "approved",
            "succeeded" if moved_items else "failed",
            f"Movidos={len(moved_items)} | falhas={len(failed_messages)}",
            correlation_id,
        )

        lines = [
            "[Quarentena] Operacao em lote de processos finalizada.",
            f"[Quarentena] Arquivos movidos com sucesso: {len(moved_items)}",
            f"[Quarentena] Arquivos com falha: {len(failed_messages)}",
        ]
        if failed_messages:
            lines.append("[Quarentena] Falhas durante a operacao em lote:")
            for message in failed_messages[:10]:
                lines.append(f"  - {message}")
            if len(failed_messages) > 10:
                lines.append(f"  - ... e mais {len(failed_messages) - 10} falha(s).")

        self._append_to_page("processes", lines)
        self._refresh_quarantine_page()
        if moved_items:
            self._switch_page("quarantine")
        self.statusBar().showMessage(
            f"Quarentena em lote de processos: {len(moved_items)} movido(s), {len(failed_messages)} falha(s)."
        )

    def _open_startup_quarantine_selection(self) -> None:
        """Permite mover executaveis de itens suspeitos de startup para quarentena."""
        if self._has_active_background_task():
            self._append_to_page("startup", ["[Quarentena] Aguarde o termino da operacao atual para mover arquivos."])
            return

        suspicious_items = list(self.last_startup_scan_report.results) if self.last_startup_scan_report else []
        if not suspicious_items:
            QMessageBox.information(
                self,
                "Nenhum item disponivel",
                (
                    "Nao ha itens de inicializacao suspeitos disponiveis para quarentena neste momento.\n\n"
                    "Quando o diagnostico gerar itens de startup suspeitos, eles aparecem aqui automaticamente."
                ),
            )
            return

        dialog = StartupQuarantineSelectionDialog(suspicious_items, self)
        if dialog.exec() != dialog.DialogCode.Accepted:
            self._append_to_page("startup", ["[Quarentena] Operacao cancelada antes da confirmacao final."])
            return

        selected_results = dialog.selected_results
        if not selected_results:
            self._append_to_page("startup", ["[Quarentena] Nenhum executavel valido foi selecionado."])
            return

        if len(selected_results) > 1:
            self._quarantine_all_startup_results(selected_results, dialog.reason)
            return

        if selected_results[0].executable_path is None:
            self._append_to_page("startup", ["[Quarentena] Nenhum executavel valido foi selecionado."])
            return

        selected_result = selected_results[0]
        policy = build_action_policy(
            action_id="quarantine_startup_single",
            title="Isolar item de inicializacao",
            description="O executavel vinculado ao item de inicializacao sera movido para a quarentena e deixara de estar disponivel no local atual.",
            severity=ActionSeverity.CRITICAL,
            confirm_label="Isolar item",
            detail_lines=(
                f"Item: {selected_result.name}",
                f"Origem: {selected_result.origin}",
                f"Risco identificado: {selected_result.risk_level.value}",
            ),
        )
        correlation_id = self._confirm_sensitive_action(
            policy,
            target_summary=f"Executavel: {selected_result.executable_path}",
        )
        if correlation_id is None:
            self._append_to_page("startup", ["[Quarentena] Confirmacao negada pelo usuario."])
            return

        try:
            quarantined_item = self.quarantine_service.quarantine_file(
                selected_result.executable_path,
                dialog.reason,
                selected_result.risk_level,
                user_confirmed=True,
            )
        except FileNotFoundError:
            self._record_action_event(policy, str(selected_result.executable_path), "approved", "failed", "Executavel nao encontrado.", correlation_id)
            QMessageBox.warning(self, "Arquivo indisponivel", "O executavel selecionado nao foi encontrado.")
            return
        except PermissionError:
            self._record_action_event(policy, str(selected_result.executable_path), "approved", "failed", "Permissao negada pelo Windows.", correlation_id)
            QMessageBox.critical(self, "Permissao negada", "O Windows negou a movimentacao do arquivo para a quarentena.")
            return
        except Exception as error:
            self._record_action_event(policy, str(selected_result.executable_path), "approved", "failed", f"Erro inesperado: {error}", correlation_id)
            log_error(self.context.logger, "Falha inesperada ao mover executavel de startup para quarentena.", error)
            QMessageBox.critical(self, "Falha na quarentena", f"Nao foi possivel concluir a quarentena: {error}")
            return

        self._record_action_event(policy, str(selected_result.executable_path), "approved", "succeeded", f"Executavel enviado para {quarantined_item.quarantined_path}", correlation_id)

        self.session_quarantine_items.append(quarantined_item)
        self._append_to_page(
            "startup",
            [
                f"[Quarentena] Executavel movido com sucesso: {quarantined_item.original_name}",
                f"[Quarentena] Destino controlado: {quarantined_item.quarantined_path}",
            ],
        )
        self._refresh_quarantine_page()
        self._switch_page("quarantine")
        self.statusBar().showMessage("Executavel de inicializacao movido para quarentena com sucesso.")

    def _quarantine_all_startup_results(self, suspicious_items: list, reason: str) -> None:
        """Move os executaveis de startup suspeitos para quarentena em lote."""
        candidates = [result for result in suspicious_items if getattr(result, "executable_path", None) is not None]
        if not candidates:
            QMessageBox.information(self, "Sem itens", "Nao ha executaveis de inicializacao disponiveis para mover.")
            return

        policy = build_action_policy(
            action_id="quarantine_startup_batch",
            title="Isolar itens de inicializacao",
            description="Todos os executaveis selecionados serao movidos para a area isolada do SentinelaPC.",
            severity=ActionSeverity.CRITICAL,
            confirm_label="Isolar itens",
            detail_lines=(
                f"Total de executaveis selecionados: {len(candidates)}",
                f"Motivo aplicado ao lote: {reason or 'Nao informado'}",
            ),
        )
        correlation_id = self._confirm_sensitive_action(
            policy,
            target_summary=f"Executaveis selecionados: {len(candidates)}",
        )
        if correlation_id is None:
            self._append_to_page("startup", ["[Quarentena] Quarentena em lote de inicializacao cancelada pelo usuario."])
            return

        moved_items = []
        failed_messages = []
        for result in candidates:
            try:
                quarantined_item = self.quarantine_service.quarantine_file(
                    result.executable_path,
                    reason,
                    result.risk_level,
                    user_confirmed=True,
                )
            except FileNotFoundError:
                failed_messages.append(f"{result.executable_path} | arquivo nao encontrado.")
                continue
            except PermissionError:
                failed_messages.append(f"{result.executable_path} | permissao negada pelo Windows.")
                continue
            except Exception as error:
                log_error(self.context.logger, "Falha inesperada ao mover executavel de inicializacao em lote para quarentena.", error)
                failed_messages.append(f"{result.executable_path} | erro: {error}")
                continue

            moved_items.append(quarantined_item)

        if moved_items:
            self.session_quarantine_items.extend(moved_items)

        self._record_action_event(
            policy,
            f"executaveis={len(candidates)}",
            "approved",
            "succeeded" if moved_items else "failed",
            f"Movidos={len(moved_items)} | falhas={len(failed_messages)}",
            correlation_id,
        )

        lines = [
            "[Quarentena] Operacao em lote de inicializacao finalizada.",
            f"[Quarentena] Arquivos movidos com sucesso: {len(moved_items)}",
            f"[Quarentena] Arquivos com falha: {len(failed_messages)}",
        ]
        if failed_messages:
            lines.append("[Quarentena] Falhas durante a operacao em lote:")
            for message in failed_messages[:10]:
                lines.append(f"  - {message}")
            if len(failed_messages) > 10:
                lines.append(f"  - ... e mais {len(failed_messages) - 10} falha(s).")

        self._append_to_page("startup", lines)
        self._refresh_quarantine_page()
        if moved_items:
            self._switch_page("quarantine")
        self.statusBar().showMessage(
            f"Quarentena em lote de inicializacao: {len(moved_items)} movido(s), {len(failed_messages)} falha(s)."
        )

    def _restore_selected_quarantine_item(self) -> None:
        """Restaura o item selecionado na pagina de quarentena para o destino original."""
        self._switch_page("quarantine")
        selected_item_id = self.quarantine_page.selected_item_id()
        if selected_item_id is None:
            QMessageBox.information(self, "Selecao obrigatoria", "Selecione um item na tabela de quarentena para restaurar.")
            return

        try:
            items = self.quarantine_service.list_items(include_restored=False)
        except Exception as error:
            log_error(self.context.logger, "Falha ao listar itens da quarentena.", error)
            QMessageBox.critical(self, "Falha ao abrir quarentena", f"Nao foi possivel carregar a lista: {error}")
            return

        selected_item = next((item for item in items if item.id == selected_item_id), None)
        if selected_item is None:
            QMessageBox.warning(self, "Item indisponivel", "O item selecionado nao esta mais disponivel.")
            return
        if selected_item.is_deleted:
            QMessageBox.information(self, "Item excluido", "O item selecionado ja foi excluido definitivamente.")
            return
        if not selected_item.is_active:
            QMessageBox.information(self, "Item ja restaurado", "O item selecionado ja foi restaurado anteriormente.")
            return

        policy = build_action_policy(
            action_id="quarantine_restore",
            title="Restaurar item da quarentena",
            description="O arquivo voltara a ficar acessivel no sistema no destino original ou em caminho alternativo seguro.",
            severity=ActionSeverity.HIGH,
            confirm_label="Restaurar item",
            detail_lines=(
                f"Arquivo: {selected_item.original_name}",
                f"Destino original: {selected_item.original_path}",
            ),
        )
        correlation_id = self._confirm_sensitive_action(
            policy,
            target_summary=f"Item em quarentena: {selected_item.quarantined_path}",
        )
        if correlation_id is None:
            self._append_dashboard_activity(["[Quarentena] Restauracao cancelada pelo usuario."])
            return

        try:
            restored_item = self.quarantine_service.restore_item(selected_item.id, user_confirmed=True)
        except PermissionError:
            self._record_action_event(policy, selected_item.original_name, "approved", "failed", "Permissao negada pelo Windows ao restaurar item.", correlation_id)
            QMessageBox.critical(self, "Permissao negada", "O Windows negou a restauracao do arquivo selecionado.")
            return
        except Exception as error:
            self._record_action_event(policy, selected_item.original_name, "approved", "failed", f"Erro inesperado: {error}", correlation_id)
            log_error(self.context.logger, "Falha ao restaurar item da quarentena.", error)
            QMessageBox.critical(self, "Falha na restauracao", f"Nao foi possivel restaurar o item: {error}")
            return

        self._record_action_event(policy, selected_item.original_name, "approved", "succeeded", f"Item restaurado para {restored_item.original_path}", correlation_id)

        self.session_quarantine_items = [restored_item if item.id == restored_item.id else item for item in self.session_quarantine_items]
        self._refresh_quarantine_page()
        lines = [
            f"[Quarentena] Item restaurado: {restored_item.original_name}",
            f"[Quarentena] Destino atual: {restored_item.original_path}",
        ]
        self._append_dashboard_activity(lines)
        self.statusBar().showMessage("Item restaurado da quarentena com sucesso.")

    def _delete_selected_quarantine_item(self) -> None:
        """Envia para a Lixeira o item selecionado na pagina de quarentena."""
        self._switch_page("quarantine")
        selected_item_id = self.quarantine_page.selected_item_id()
        if selected_item_id is None:
            QMessageBox.information(self, "Selecao obrigatoria", "Selecione um item na tabela de quarentena para excluir.")
            return

        try:
            items = self.quarantine_service.list_items(include_restored=False)
        except Exception as error:
            log_error(self.context.logger, "Falha ao listar itens da quarentena para exclusao.", error)
            QMessageBox.critical(self, "Falha ao abrir quarentena", f"Nao foi possivel carregar a lista: {error}")
            return

        selected_item = next((item for item in items if item.id == selected_item_id), None)
        if selected_item is None:
            QMessageBox.warning(self, "Item indisponivel", "O item selecionado nao esta mais disponivel.")
            return
        if selected_item.is_deleted:
            QMessageBox.information(self, "Item ja excluido", "O item selecionado ja foi excluido anteriormente.")
            return
        if not selected_item.is_active:
            QMessageBox.information(self, "Exclusao indisponivel", "Somente itens ainda ativos na quarentena podem ser excluidos definitivamente.")
            return

        policy = build_action_policy(
            action_id="quarantine_delete",
            title="Excluir item ativo da quarentena",
            description="O arquivo sera enviado para a Lixeira e deixara a lista ativa de quarentena. O registro de auditoria sera mantido.",
            severity=ActionSeverity.CRITICAL,
            confirm_label="Enviar para a Lixeira",
            irreversible=True,
            confirm_phrase="EXCLUIR",
            detail_lines=(
                f"Arquivo: {selected_item.original_name}",
                f"Local isolado: {selected_item.quarantined_path}",
            ),
        )
        correlation_id = self._confirm_sensitive_action(
            policy,
            target_summary=f"Item ativo: {selected_item.original_name}",
        )
        if correlation_id is None:
            self._append_dashboard_activity(["[Quarentena] Envio para a Lixeira cancelado pelo usuario."])
            return

        try:
            deleted_item = self.quarantine_service.delete_item(selected_item.id, user_confirmed=True)
        except PermissionError:
            self._record_action_event(policy, selected_item.original_name, "approved", "failed", "Permissao negada pelo Windows ao enviar item para a Lixeira.", correlation_id)
            QMessageBox.critical(self, "Permissao negada", "O Windows negou o envio do arquivo para a Lixeira.")
            return
        except Exception as error:
            self._record_action_event(policy, selected_item.original_name, "approved", "failed", f"Erro inesperado: {error}", correlation_id)
            log_error(self.context.logger, "Falha ao excluir item da quarentena.", error)
            QMessageBox.critical(self, "Falha na exclusao", f"Nao foi possivel enviar o item para a Lixeira: {error}")
            return

        self._record_action_event(policy, selected_item.original_name, "approved", "succeeded", "Item enviado para a Lixeira e mantido apenas no historico.", correlation_id)

        self.session_quarantine_items = [deleted_item if item.id == deleted_item.id else item for item in self.session_quarantine_items]
        self._refresh_quarantine_page()
        lines = [
            f"[Quarentena] Item enviado para a Lixeira: {deleted_item.original_name}",
            f"[Quarentena] Registro mantido para auditoria com status: {deleted_item.status}",
        ]
        self._append_dashboard_activity(lines)
        self.statusBar().showMessage("Item enviado para a Lixeira e removido da lista ativa.")

    def _refresh_quarantine_page(self) -> None:
        """Atualiza a tela de quarentena com o estado mais recente do banco local."""
        try:
            # Mostra apenas itens ativos; restaurados e enviados para Lixeira saem da lista.
            items = self.quarantine_service.list_items(include_restored=False)
        except Exception as error:
            log_error(self.context.logger, "Falha ao listar itens da quarentena.", error)
            self.dashboard_page.append_activity([f"[Quarentena] Falha ao atualizar lista: {error}"])
            return
        self.quarantine_page.populate_items(items)

    def _refresh_history_page(self) -> None:
        """Atualiza a tela de historico com as entradas persistidas mais recentes."""
        try:
            entries = self.history_repository.list_history()
        except Exception as error:
            log_error(self.context.logger, "Falha ao carregar historico de verificacoes.", error)
            self.dashboard_page.append_activity([f"[Historico] Falha ao carregar dados: {error}"])
            return
        self.history_page.populate_entries(entries)

    def _save_history_entry(self, record: HistoryRecordInput) -> None:
        """Salva uma entrada no historico sem interromper o restante da interface."""
        try:
            self.history_repository.save_result(record)
        except Exception as error:
            log_error(self.context.logger, "Falha ao salvar historico de verificacoes.", error)

    def _has_active_background_task(self) -> bool:
        """Indica se existe algum worker rodando em segundo plano."""
        return any(
            thread is not None
            for thread in (
                self.scan_thread,
                self.process_thread,
                self.startup_thread,
                self.diagnostics_thread,
                self.browser_thread,
                self.email_thread,
                self.audit_thread,
            )
        )

    def _set_busy_actions(self, enabled: bool) -> None:
        """Liga ou desliga botoes de operacoes demoradas em todas as paginas relevantes."""
        self.dashboard_page.actions_panel.set_action_enabled("quick_scan", enabled)
        self.dashboard_page.actions_panel.set_action_enabled("full_scan", enabled)
        self.dashboard_page.actions_panel.set_action_enabled("pause_scan", False)
        self.dashboard_page.actions_panel.set_action_enabled("stop_scan", False)
        self.dashboard_page.actions_panel.set_action_enabled("process_scan", enabled)
        self.dashboard_page.actions_panel.set_action_enabled("startup_scan", enabled)
        self.dashboard_page.actions_panel.set_action_enabled("diagnostics", enabled)
        self.dashboard_page.actions_panel.set_action_enabled("generate_report", enabled)
        self.files_page.set_action_enabled("quick_scan", enabled)
        self.files_page.set_action_enabled("full_scan", enabled)
        self.files_page.set_action_enabled("quarantine_file", enabled)
        self.processes_page.set_action_enabled("process_scan", enabled)
        self.processes_page.set_action_enabled("quarantine_process", enabled)
        self.startup_page.set_action_enabled("startup_scan", enabled)
        self.startup_page.set_action_enabled("quarantine_startup", enabled)
        self.browsers_page.set_action_enabled("browser_scan", enabled)
        self.browsers_page.set_action_enabled("browser_view_suspicious", enabled)
        self.emails_page.set_action_enabled("email_connect_gmail", enabled)
        self.emails_page.set_action_enabled("email_connect_outlook", enabled)
        self.emails_page.set_action_enabled("email_scan_online", enabled)
        self.emails_page.set_action_enabled("email_disconnect_account", enabled)
        self.emails_page.set_action_enabled("email_scan_file", enabled)
        self.emails_page.set_action_enabled("email_scan_folder", enabled)
        self.audit_page.set_action_enabled("audit_run", enabled)
        self.diagnostics_page.set_action_enabled("diagnostics", enabled)
        self.diagnostics_page.set_action_enabled("quarantine_file", enabled)
        self.diagnostics_page.set_action_enabled("quarantine_process", enabled)
        self.diagnostics_page.set_action_enabled("quarantine_startup", enabled)
        self.reports_page.set_action_enabled("generate_report", enabled)

    def _set_file_scan_control_actions(self, enabled: bool) -> None:
        """Controla os botoes de pausa e parada da verificacao de arquivos."""
        self.dashboard_page.actions_panel.set_action_enabled("pause_scan", enabled)
        self.dashboard_page.actions_panel.set_action_enabled("stop_scan", enabled)
        self.files_page.set_action_enabled("pause_scan", enabled)
        self.files_page.set_action_enabled("stop_scan", enabled)

    def _set_process_scan_control_actions(self, enabled: bool) -> None:
        """Controla os botoes de pausa e parada da verificacao de processos."""
        self.processes_page.set_action_enabled("pause_process_scan", enabled)
        self.processes_page.set_action_enabled("stop_process_scan", enabled)

    def _set_startup_scan_control_actions(self, enabled: bool) -> None:
        """Controla os botoes de pausa e parada da verificacao de inicializacao."""
        self.startup_page.set_action_enabled("pause_startup_scan", enabled)
        self.startup_page.set_action_enabled("stop_startup_scan", enabled)

    def _set_diagnostics_control_actions(self, enabled: bool) -> None:
        """Controla os botoes de pausa e parada do diagnostico."""
        self.diagnostics_page.set_action_enabled("pause_diagnostics", enabled)
        self.diagnostics_page.set_action_enabled("stop_diagnostics", enabled)

    def _set_browser_scan_control_actions(self, enabled: bool) -> None:
        """Controla os botoes de pausa e parada da analise de navegadores."""
        self.browsers_page.set_action_enabled("pause_browser_scan", enabled)
        self.browsers_page.set_action_enabled("stop_browser_scan", enabled)

    def _set_email_scan_control_actions(self, enabled: bool) -> None:
        """Controla os botoes de pausa e parada da analise de e-mails."""
        self.emails_page.set_action_enabled("pause_email_scan", enabled)
        self.emails_page.set_action_enabled("stop_email_scan", enabled)

    def _set_audit_control_actions(self, enabled: bool) -> None:
        """Controla botoes da auditoria avancada."""
        self.audit_page.set_action_enabled("audit_stop", enabled)
        self.audit_page.set_action_enabled("audit_resolve", not enabled and self.last_audit_report is not None)
        export_enabled = (not enabled) and self.last_audit_report is not None
        self.audit_page.set_action_enabled("export_audit_txt", export_enabled)
        self.audit_page.set_action_enabled("export_audit_json", export_enabled)

    def _prepare_operation_page(self, page_id: str, initial_lines: list[str]) -> None:
        """Seleciona a pagina do modulo e limpa o console antes de uma nova execucao."""
        self._switch_page(page_id)
        self._active_operation_page_id = page_id
        page = self._get_operation_page(page_id)
        if page is not None:
            page.clear()
            page.append_lines(initial_lines)
        self._append_dashboard_activity(initial_lines)

    def _start_visual_progress(self, page_id: str, task_name: str) -> None:
        """Inicia animacao de progresso estilo instalacao para o modulo ativo."""
        self._visual_progress_page_id = page_id
        self._visual_progress_value = 0
        self._visual_progress_paused = False
        target = self._get_progress_target_page(page_id)
        if target is not None:
            if page_id == "audit":
                target.start_progress()
            else:
                target.start_progress(task_name)
        self._visual_progress_timer.start()

    def _tick_visual_progress(self) -> None:
        """Avanca o percentual gradualmente ate proximo de 100% enquanto o worker executa."""
        if self._visual_progress_page_id is None or self._visual_progress_paused:
            return

        if self._visual_progress_value < 38:
            increment = 3
        elif self._visual_progress_value < 70:
            increment = 2
        elif self._visual_progress_value < 92:
            increment = 1
        elif self._visual_progress_value < 98:
            increment = 1 if (self._visual_progress_value % 2 == 0) else 0
        else:
            increment = 0

        self._visual_progress_value = min(98, self._visual_progress_value + increment)
        target = self._get_progress_target_page(self._visual_progress_page_id)
        if target is not None:
            target.set_progress(self._visual_progress_value)

    def _touch_visual_progress(self, phase_message: str) -> None:
        """Atualiza a fase textual e empurra levemente o progresso quando houver evento real."""
        if self._visual_progress_page_id is None:
            return

        if self._visual_progress_value < 98:
            self._visual_progress_value += 1

        target = self._get_progress_target_page(self._visual_progress_page_id)
        if target is not None:
            target.set_progress(self._visual_progress_value, phase=phase_message)

    def _set_visual_progress_paused(self, paused: bool) -> None:
        """Congela/descongela a animacao de progresso quando o worker esta pausado."""
        self._visual_progress_paused = paused
        if self._visual_progress_page_id is None:
            return
        target = self._get_progress_target_page(self._visual_progress_page_id)
        if target is not None and hasattr(target, "set_progress_paused"):
            target.set_progress_paused(paused)

    def _finish_visual_progress(self, page_id: str, interrupted: bool) -> None:
        """Finaliza o progresso visual quando a operacao encerra (sucesso/falha/cancelamento)."""
        if self._visual_progress_page_id != page_id:
            return

        self._visual_progress_timer.stop()
        target = self._get_progress_target_page(page_id)
        if target is not None:
            target.finish_progress(interrupted=interrupted)

        self._visual_progress_page_id = None
        self._visual_progress_paused = False

    def _get_progress_target_page(self, page_id: str):
        """Retorna a pagina que possui o componente visual de progresso."""
        if page_id == "audit":
            return self.audit_page
        return self._get_operation_page(page_id)

    def _connect_background_worker(
        self,
        thread: QThread,
        worker,
        success_handler,
        failure_handler,
        cleanup_handler,
    ) -> None:
        """Centraliza a ligacao entre thread, worker, progresso e limpeza final."""
        thread.started.connect(worker.run)
        worker.progress.connect(self._append_scan_progress)
        worker.finished.connect(success_handler)
        worker.failed.connect(failure_handler)
        worker.finished.connect(thread.quit)
        worker.failed.connect(thread.quit)
        thread.finished.connect(cleanup_handler)

    def _cleanup_worker_resources(self, worker_attr_name: str, thread_attr_name: str) -> None:
        """Libera worker e thread usando os nomes dos atributos para evitar codigo duplicado."""
        worker = getattr(self, worker_attr_name)
        thread = getattr(self, thread_attr_name)

        if worker is not None:
            worker.deleteLater()
        if thread is not None:
            thread.deleteLater()

        setattr(self, worker_attr_name, None)
        setattr(self, thread_attr_name, None)

    def _report_background_failure(
        self,
        page_id: str,
        display_prefix: str,
        status_message: str,
        log_message: str,
        error_message: str,
        report_attr_name: str | None = None,
    ) -> None:
        """Padroniza falhas de workers sem repetir log, status e atualizacao visual."""
        if report_attr_name is not None:
            setattr(self, report_attr_name, None)

        self._append_to_page(page_id, [f"{display_prefix}: {error_message}"])
        self.statusBar().showMessage(status_message)
        log_error(self.context.logger, log_message, RuntimeError(error_message))

    def _append_to_page(self, page_id: str, lines: list[str]) -> None:
        """Adiciona linhas a uma pagina operacional sem perder o historico do dashboard."""
        page = self._get_operation_page(page_id)
        if page is not None:
            page.append_lines(lines)
        self._append_dashboard_activity(lines)

    def _append_dashboard_activity(self, lines: list[str]) -> None:
        """Replica mensagens relevantes no painel de atividade da dashboard."""
        self.dashboard_page.append_activity(lines)

    def _get_operation_page(self, page_id: str) -> OperationPage | None:
        """Retorna a pagina operacional correspondente ao identificador solicitado."""
        mapping = {
            "files": self.files_page,
            "processes": self.processes_page,
            "startup": self.startup_page,
            "browsers": self.browsers_page,
            "emails": self.emails_page,
            "diagnostics": self.diagnostics_page,
        }
        return mapping.get(page_id)


    def _register_executed_scan(self, scan_label: str) -> None:
        """Mantem uma lista enxuta dos tipos de analise executados na sessao."""
        if scan_label not in self.executed_scan_types:
            self.executed_scan_types.append(scan_label)
