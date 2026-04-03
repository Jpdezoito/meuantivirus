"""Paginas principais usadas pela interface reorganizada do SentinelaPC."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QProgressBar,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)
from PySide6.QtGui import QColor
from PySide6.QtWidgets import QAbstractItemView, QComboBox

from app.core.bootstrap import ApplicationContext
from app.data.history_models import HistoryEntry
from app.services.audit_models import AuditCategory, AuditFinding, AuditReport, AuditSeverity, AuditStatus
from app.services.quarantine_models import QuarantineItem
from app.ui.panels import ActionsPanel, HeroStatusCard, ResultsPanel, SystemStatusPanel
from app.ui.widgets import ActionButton, CardFrame, MetricCard, SectionHeader


class DashboardPage(QWidget):
    """Pagina inicial com hero de status, tiles de acao e log da sessao."""

    action_requested = Signal(str)

    def __init__(self, context: ApplicationContext, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(16)

        # Hero card de status no topo
        self.hero_card = HeroStatusCard()
        layout.addWidget(self.hero_card)

        # Grid inferior: acoes (esquerda larga) + atividade (direita)
        content = QGridLayout()
        content.setHorizontalSpacing(16)
        content.setVerticalSpacing(16)

        self.system_status_panel = SystemStatusPanel(context)
        self.actions_panel = ActionsPanel()
        self.activity_panel = ResultsPanel()

        self.actions_panel.action_requested.connect(self.action_requested.emit)

        content.addWidget(self.system_status_panel, 0, 0, 1, 2)
        content.addWidget(self.actions_panel, 1, 0, 1, 2)
        content.addWidget(self.activity_panel, 2, 0, 1, 2)
        content.setColumnStretch(0, 1)
        content.setColumnStretch(1, 1)

        layout.addLayout(content, 1)

    def append_activity(self, lines: Sequence[str]) -> None:
        """Adiciona mensagens ao painel de atividade da sessao."""
        self.activity_panel.append_lines(lines)


class OperationPage(QWidget):
    """Pagina reutilizavel para modulos que exibem log e resumo operacional."""

    action_requested = Signal(str)

    def __init__(
        self,
        eyebrow: str,
        title: str,
        description: str,
        actions: Sequence[tuple[str, str]],
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._action_buttons: dict[str, ActionButton] = {}
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(18)

        eyebrow_label = QLabel(eyebrow)
        eyebrow_label.setObjectName("pageEyebrow")
        title_label = QLabel(title)
        title_label.setObjectName("pageTitleLarge")
        description_label = QLabel(description)
        description_label.setObjectName("pageSubtitle")
        description_label.setWordWrap(True)

        layout.addWidget(eyebrow_label)
        layout.addWidget(title_label)
        layout.addWidget(description_label)

        metrics_layout = QHBoxLayout()
        metrics_layout.setSpacing(14)

        self.analyzed_metric = MetricCard(
            "Itens analisados",
            "0",
            "Volume avaliado na ultima execucao deste modulo.",
        )
        self.suspicious_metric = MetricCard(
            "Itens suspeitos",
            "0",
            "Quantidade sinalizada ou considerada relevante.",
        )
        self.session_metric = MetricCard(
            "Ultima atualizacao",
            "--",
            "Horario do ultimo resultado mostrado nesta tela.",
        )

        metrics_layout.addWidget(self.analyzed_metric)
        metrics_layout.addWidget(self.suspicious_metric)
        metrics_layout.addWidget(self.session_metric)
        layout.addLayout(metrics_layout)

        progress_card = CardFrame()
        progress_layout = QVBoxLayout(progress_card)
        progress_layout.setContentsMargins(20, 16, 20, 16)
        progress_layout.setSpacing(8)
        self.progress_title = QLabel("Progresso da verificacao")
        self.progress_title.setObjectName("sectionTitle")
        self.progress_phase = QLabel("Aguardando inicio...")
        self.progress_phase.setObjectName("sectionDescription")
        self.progress_percent = QLabel("0%")
        self.progress_percent.setObjectName("progressPercentLabel")
        self.progress_percent.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)

        progress_header = QHBoxLayout()
        progress_header.setContentsMargins(0, 0, 0, 0)
        progress_header.setSpacing(8)
        progress_header.addWidget(self.progress_title, 1)
        progress_header.addWidget(self.progress_percent)

        self.progress_bar = QProgressBar()
        self.progress_bar.setObjectName("scanProgressBar")
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setTextVisible(False)

        progress_layout.addLayout(progress_header)
        progress_layout.addWidget(self.progress_bar)
        progress_layout.addWidget(self.progress_phase)
        layout.addWidget(progress_card)

        action_card = CardFrame()
        action_layout = QHBoxLayout(action_card)
        action_layout.setContentsMargins(20, 18, 20, 18)
        action_layout.setSpacing(12)

        for action_key, label in actions:
            button = ActionButton(action_key, label)
            button.setMinimumHeight(46)
            button.triggered.connect(self.action_requested.emit)
            self._action_buttons[action_key] = button
            action_layout.addWidget(button)

        action_layout.addStretch()
        layout.addWidget(action_card)

        navigation_card = CardFrame()
        navigation_layout = QHBoxLayout(navigation_card)
        navigation_layout.setContentsMargins(20, 18, 20, 18)
        navigation_layout.setSpacing(12)
        navigation_layout.addWidget(
            SectionHeader(
                "Acesso rapido",
                "Volte ao painel principal ou navegue direto para as areas mais usadas sem depender apenas da barra lateral.",
            )
        )
        navigation_layout.addStretch()

        for action_key, label in (
            ("open_dashboard", "Pagina principal"),
            ("open_quarantine", "Quarentena"),
            ("open_history", "Historico"),
        ):
            button = ActionButton(action_key, label, style_variant="secondary")
            button.setMinimumHeight(44)
            button.triggered.connect(self.action_requested.emit)
            navigation_layout.addWidget(button)

        layout.addWidget(navigation_card)

        self.console_card = CardFrame()
        console_layout = QVBoxLayout(self.console_card)
        console_layout.setContentsMargins(20, 18, 20, 18)
        console_layout.setSpacing(14)
        console_layout.addWidget(
            SectionHeader(
                "Resultado operacional",
                "Saida textual detalhada da ultima execucao deste modulo.",
            )
        )

        self.console = QTextEdit()
        self.console.setObjectName("pageConsole")
        self.console.setReadOnly(True)
        console_layout.addWidget(self.console)
        layout.addWidget(self.console_card, 1)

    def append_lines(self, lines: Sequence[str]) -> None:
        """Adiciona linhas ao console principal desta tela."""
        for line in lines:
            self.console.append(line)

    def clear(self) -> None:
        """Limpa o console antes de uma nova execucao do modulo."""
        self.console.clear()

    def update_summary(self, analyzed: int, suspicious: int, stamp: str) -> None:
        """Atualiza os cards superiores com o ultimo resultado disponivel."""
        self.analyzed_metric.set_value(str(analyzed))
        self.suspicious_metric.set_value(str(suspicious))
        self.session_metric.set_value(stamp)

    def set_action_enabled(self, action_key: str, enabled: bool) -> None:
        """Liga ou desliga um botao especifico desta tela operacional."""
        button = self._action_buttons.get(action_key)
        if button is not None:
            button.setEnabled(enabled)

    def start_progress(self, task_name: str) -> None:
        """Reseta o indicador visual de progresso para uma nova execucao."""
        self.progress_title.setText(f"Progresso da verificacao - {task_name}")
        self.progress_bar.setValue(0)
        self.progress_percent.setText("0%")
        self.progress_phase.setText("Inicializando modulo...")

    def set_progress(self, percent: int, phase: str | None = None) -> None:
        """Atualiza percentual e fase atual do progresso."""
        bounded = max(0, min(100, int(percent)))
        self.progress_bar.setValue(bounded)
        self.progress_percent.setText(f"{bounded}%")
        if phase:
            self.progress_phase.setText(phase)

    def set_progress_paused(self, paused: bool) -> None:
        """Ajusta texto de fase quando o modulo entra em pausa ou retoma."""
        if paused:
            self.progress_phase.setText("Pausado pelo usuario. Aguardando retomada...")
            return
        self.progress_phase.setText("Retomando verificacao...")

    def finish_progress(self, interrupted: bool = False) -> None:
        """Finaliza o indicador visual de progresso."""
        if interrupted:
            current = self.progress_bar.value()
            self.progress_bar.setValue(max(0, min(99, current)))
            self.progress_percent.setText(f"{self.progress_bar.value()}%")
            self.progress_phase.setText("Verificacao interrompida pelo usuario.")
            return
        self.progress_bar.setValue(100)
        self.progress_percent.setText("100%")
        self.progress_phase.setText("Verificacao concluida.")


class QuarantinePage(QWidget):
    """Tela dedicada para consulta e manutencao dos itens em quarentena."""

    action_requested = Signal(str)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(18)

        layout.addWidget(self._build_heading("Isolamento seguro", "Quarentena"))
        layout.addWidget(self._build_subtitle(
            "Consulte os arquivos isolados, acompanhe o status de restauracao e atualize a lista sem sair da interface principal."
        ))

        metrics_layout = QHBoxLayout()
        metrics_layout.setSpacing(14)
        self.total_metric = MetricCard("Total", "0", "Quantidade total registrada no banco local.")
        self.active_metric = MetricCard("Ativos", "0", "Itens ainda mantidos na pasta de quarentena.")
        self.restored_metric = MetricCard("Restaurados", "0", "Itens que ja foram devolvidos ao destino.")
        self.deleted_metric = MetricCard("Excluidos", "0", "Itens removidos definitivamente da pasta de quarentena.")
        metrics_layout.addWidget(self.total_metric)
        metrics_layout.addWidget(self.active_metric)
        metrics_layout.addWidget(self.restored_metric)
        metrics_layout.addWidget(self.deleted_metric)
        layout.addLayout(metrics_layout)

        actions = CardFrame()
        actions_layout = QHBoxLayout(actions)
        actions_layout.setContentsMargins(20, 18, 20, 18)
        actions_layout.setSpacing(12)
        for action_key, label, variant in (
            ("open_dashboard", "Pagina principal", "secondary"),
            ("open_files", "Arquivos suspeitos", "secondary"),
            ("refresh_quarantine", "Atualizar lista", "primary"),
            ("restore_quarantine", "Restaurar selecionado", "primary"),
            ("delete_quarantine", "Excluir selecionado", "primary"),
        ):
            button = ActionButton(action_key, label, style_variant=variant)
            button.setMinimumHeight(46)
            button.triggered.connect(self.action_requested.emit)
            actions_layout.addWidget(button)
        actions_layout.addStretch()
        layout.addWidget(actions)

        self.table = self._build_table([
            "ID",
            "Nome original",
            "Risco",
            "Status",
            "Motivo",
            "Origem",
            "Destino na quarentena",
            "Data",
        ])
        layout.addWidget(self.table, 1)

    def populate_items(self, items: Sequence[QuarantineItem]) -> None:
        """Atualiza a tabela e os indicadores da quarentena."""
        self.table.setRowCount(len(items))
        active_count = 0
        restored_count = 0
        deleted_count = 0
        for row_index, item in enumerate(items):
            if item.is_active:
                active_count += 1
            elif item.is_deleted:
                deleted_count += 1
            else:
                restored_count += 1

            values = [
                str(item.id),
                item.original_name,
                item.risk_level.value,
                item.status,
                item.reason,
                str(item.original_path),
                str(item.quarantined_path),
                item.created_at,
            ]
            for column, value in enumerate(values):
                self.table.setItem(row_index, column, QTableWidgetItem(value))

        self.total_metric.set_value(str(len(items)))
        self.active_metric.set_value(str(active_count))
        self.restored_metric.set_value(str(restored_count))
        self.deleted_metric.set_value(str(deleted_count))

    def selected_item_id(self) -> int | None:
        """Retorna o identificador da linha selecionada para restauracao."""
        selected_row = self.table.currentRow()
        if selected_row < 0:
            return None
        item = self.table.item(selected_row, 0)
        if item is None:
            return None
        return int(item.text())

    def _build_heading(self, eyebrow: str, title: str) -> QWidget:
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(4)
        eyebrow_label = QLabel(eyebrow)
        eyebrow_label.setObjectName("pageEyebrow")
        title_label = QLabel(title)
        title_label.setObjectName("pageTitleLarge")
        layout.addWidget(eyebrow_label)
        layout.addWidget(title_label)
        return container

    def _build_subtitle(self, text: str) -> QLabel:
        subtitle = QLabel(text)
        subtitle.setObjectName("pageSubtitle")
        subtitle.setWordWrap(True)
        return subtitle

    def _build_table(self, headers: Sequence[str]) -> QTableWidget:
        table = QTableWidget(0, len(headers))
        table.setObjectName("dataTable")
        table.setHorizontalHeaderLabels(list(headers))
        table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        table.verticalHeader().setVisible(False)
        table.horizontalHeader().setStretchLastSection(True)
        table.setAlternatingRowColors(True)
        return table


class HistoryPage(QWidget):
    """Tela dedicada para consulta das verificacoes persistidas no banco."""

    action_requested = Signal(str)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(18)

        header = QWidget()
        header_layout = QVBoxLayout(header)
        header_layout.setContentsMargins(0, 0, 0, 0)
        header_layout.setSpacing(4)
        eyebrow = QLabel("Auditoria local")
        eyebrow.setObjectName("pageEyebrow")
        title = QLabel("Historico")
        title.setObjectName("pageTitleLarge")
        subtitle = QLabel(
            "Visualize o historico das verificacoes realizadas, com volumes analisados, achados resumidos e referencias a relatorios gerados."
        )
        subtitle.setObjectName("pageSubtitle")
        subtitle.setWordWrap(True)
        header_layout.addWidget(eyebrow)
        header_layout.addWidget(title)
        header_layout.addWidget(subtitle)
        layout.addWidget(header)

        action_card = CardFrame()
        action_layout = QHBoxLayout(action_card)
        action_layout.setContentsMargins(20, 18, 20, 18)
        for action_key, label, variant in (
            ("open_dashboard", "Pagina principal", "secondary"),
            ("open_quarantine", "Quarentena", "secondary"),
            ("refresh_history", "Atualizar historico", "primary"),
        ):
            button = ActionButton(action_key, label, style_variant=variant)
            button.setMinimumHeight(46)
            button.triggered.connect(self.action_requested.emit)
            action_layout.addWidget(button)
        action_layout.addStretch()
        layout.addWidget(action_card)

        self.table = QTableWidget(0, 6)
        self.table.setObjectName("dataTable")
        self.table.setHorizontalHeaderLabels(["Data/Hora", "Tipo", "Analisados", "Suspeitos", "Resumo", "Relatorio"])
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setAlternatingRowColors(True)
        layout.addWidget(self.table, 1)

    def populate_entries(self, entries: Sequence[HistoryEntry]) -> None:
        """Atualiza a tabela de historico com as entradas recuperadas do banco."""
        self.table.setRowCount(len(entries))
        for row_index, entry in enumerate(entries):
            values = [
                entry.created_at,
                entry.scan_type,
                str(entry.analyzed_count),
                str(entry.suspicious_count),
                entry.summary,
                entry.report_path or "-",
            ]
            for column, value in enumerate(values):
                self.table.setItem(row_index, column, QTableWidgetItem(value))


class ReportsPage(QWidget):
    """Tela dedicada aos relatorios gerados durante a sessao atual."""

    action_requested = Signal(str)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._rows: list[tuple[str, str, str]] = []
        self._generate_button: ActionButton | None = None

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(18)

        layout.addWidget(self._build_heading("Documentacao operacional", "Relatorios"))
        subtitle = QLabel(
            "Gere e acompanhe os arquivos TXT e HTML produzidos a partir dos resultados acumulados na sessao atual."
        )
        subtitle.setObjectName("pageSubtitle")
        subtitle.setWordWrap(True)
        layout.addWidget(subtitle)

        metrics_layout = QHBoxLayout()
        metrics_layout.setSpacing(14)
        self.total_metric = MetricCard("Relatorios", "0", "Quantidade gerada nesta sessao.")
        self.last_metric = MetricCard("Ultimo formato", "--", "Ultimo arquivo registrado na tela.")
        self.path_metric = MetricCard("Sessao", "Ativa", "Relatorios podem ser regenerados a qualquer momento.")
        metrics_layout.addWidget(self.total_metric)
        metrics_layout.addWidget(self.last_metric)
        metrics_layout.addWidget(self.path_metric)
        layout.addLayout(metrics_layout)

        action_card = CardFrame()
        action_layout = QHBoxLayout(action_card)
        action_layout.setContentsMargins(20, 18, 20, 18)
        dashboard_button = ActionButton("open_dashboard", "Pagina principal", style_variant="secondary")
        dashboard_button.setMinimumHeight(46)
        dashboard_button.triggered.connect(self.action_requested.emit)
        action_layout.addWidget(dashboard_button)

        history_button = ActionButton("open_history", "Historico", style_variant="secondary")
        history_button.setMinimumHeight(46)
        history_button.triggered.connect(self.action_requested.emit)
        action_layout.addWidget(history_button)

        generate_button = ActionButton("generate_report", "Gerar relatorio")
        generate_button.setMinimumHeight(46)
        generate_button.triggered.connect(self.action_requested.emit)
        self._generate_button = generate_button
        action_layout.addWidget(generate_button)
        action_layout.addStretch()
        layout.addWidget(action_card)

        self.table = QTableWidget(0, 3)
        self.table.setObjectName("dataTable")
        self.table.setHorizontalHeaderLabels(["Momento", "Arquivo TXT", "Arquivo HTML"])
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setAlternatingRowColors(True)
        layout.addWidget(self.table, 1)

    def add_report(self, created_at: str, txt_path: Path, html_path: Path) -> None:
        """Registra um novo relatorio gerado na sessao e atualiza a tabela."""
        self._rows.insert(0, (created_at, str(txt_path), str(html_path)))
        self._refresh_table()

    def _refresh_table(self) -> None:
        """Recarrega a grade de relatorios com base nas linhas da sessao."""
        self.table.setRowCount(len(self._rows))
        for row_index, row in enumerate(self._rows):
            for column, value in enumerate(row):
                self.table.setItem(row_index, column, QTableWidgetItem(value))

        self.total_metric.set_value(str(len(self._rows)))
        if self._rows:
            self.last_metric.set_value("TXT + HTML")
            self.path_metric.set_value(self._rows[0][0])

    def _build_heading(self, eyebrow: str, title: str) -> QWidget:
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(4)
        eyebrow_label = QLabel(eyebrow)
        eyebrow_label.setObjectName("pageEyebrow")
        title_label = QLabel(title)
        title_label.setObjectName("pageTitleLarge")
        layout.addWidget(eyebrow_label)
        layout.addWidget(title_label)
        return container

    def set_action_enabled(self, action_key: str, enabled: bool) -> None:
        """Liga ou desliga o botao de geracao desta tela."""
        if action_key == "generate_report" and self._generate_button is not None:
            self._generate_button.setEnabled(enabled)


_SEVERITY_COLORS: dict[str, QColor] = {
    AuditSeverity.CRITICAL: QColor("#e74c3c"),
    AuditSeverity.HIGH: QColor("#e67e22"),
    AuditSeverity.MEDIUM: QColor("#f39c12"),
    AuditSeverity.LOW: QColor("#d4ac0d"),
    AuditSeverity.INFORMATIVE: QColor("#7f8c8d"),
}

_STATUS_COLORS: dict[str, QColor] = {
    AuditStatus.CRITICAL: QColor("#e74c3c"),
    AuditStatus.VULNERABLE: QColor("#e67e22"),
    AuditStatus.ATTENTION: QColor("#f39c12"),
    AuditStatus.SAFE: QColor("#27ae60"),
    AuditStatus.UNKNOWN: QColor("#7f8c8d"),
}


class AuditPage(QWidget):
    """Pagina dedicada ao modulo de Auditoria Avancada de Seguranca."""

    action_requested = Signal(str)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._action_buttons: dict[str, ActionButton] = {}
        self._current_findings: list[AuditFinding] = []
        self._visible_row_to_finding: dict[int, int] = {}

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(18)

        eyebrow = QLabel("Seguranca avancada do sistema")
        eyebrow.setObjectName("pageEyebrow")
        title = QLabel("Auditoria Avancada")
        title.setObjectName("pageTitleLarge")
        subtitle = QLabel(
            "Verificacao tecnica de configuracoes de seguranca, firewall, acesso remoto, privacidade e protecao de dados. "
            "Cada achado inclui evidencia e recomendacao."
        )
        subtitle.setObjectName("pageSubtitle")
        subtitle.setWordWrap(True)
        layout.addWidget(eyebrow)
        layout.addWidget(title)
        layout.addWidget(subtitle)

        metrics_layout = QHBoxLayout()
        metrics_layout.setSpacing(14)
        self.score_metric = MetricCard("Score Total", "--", "Soma dos scores de todos os achados de risco.")
        self.issues_metric = MetricCard("Problemas", "--", "Quantidade de achados com status diferente de Seguro.")
        self.status_metric = MetricCard("Status Geral", "--", "Classificacao geral da auditoria.")
        self.stamp_metric = MetricCard("Ultima execucao", "--", "Horario da ultima auditoria concluida.")
        metrics_layout.addWidget(self.score_metric)
        metrics_layout.addWidget(self.issues_metric)
        metrics_layout.addWidget(self.status_metric)
        metrics_layout.addWidget(self.stamp_metric)
        layout.addLayout(metrics_layout)

        progress_card = CardFrame()
        progress_layout = QVBoxLayout(progress_card)
        progress_layout.setContentsMargins(20, 16, 20, 16)
        progress_layout.setSpacing(8)
        self._progress_title = QLabel("Progresso da auditoria")
        self._progress_title.setObjectName("sectionTitle")
        self._progress_phase = QLabel("Aguardando inicio...")
        self._progress_phase.setObjectName("sectionDescription")
        self._progress_percent = QLabel("0%")
        self._progress_percent.setObjectName("progressPercentLabel")
        self._progress_percent.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)

        progress_header = QHBoxLayout()
        progress_header.setContentsMargins(0, 0, 0, 0)
        progress_header.setSpacing(8)
        progress_header.addWidget(self._progress_title, 1)
        progress_header.addWidget(self._progress_percent)

        self._progress_bar = QProgressBar()
        self._progress_bar.setObjectName("scanProgressBar")
        self._progress_bar.setRange(0, 100)
        self._progress_bar.setValue(0)
        self._progress_bar.setTextVisible(False)

        progress_layout.addLayout(progress_header)
        progress_layout.addWidget(self._progress_bar)
        progress_layout.addWidget(self._progress_phase)
        layout.addWidget(progress_card)

        action_card = CardFrame()
        action_layout = QHBoxLayout(action_card)
        action_layout.setContentsMargins(20, 18, 20, 18)
        action_layout.setSpacing(12)
        for action_key, label in (
            ("audit_run", "Executar Auditoria"),
            ("audit_stop", "Parar Auditoria"),
            ("audit_resolve", "Resolver problemas"),
            ("export_audit_txt", "Exportar TXT"),
            ("export_audit_json", "Exportar JSON"),
        ):
            button = ActionButton(action_key, label)
            button.setMinimumHeight(46)
            button.triggered.connect(self.action_requested.emit)
            self._action_buttons[action_key] = button
            action_layout.addWidget(button)
        action_layout.addStretch()
        layout.addWidget(action_card)

        filter_card = CardFrame()
        filter_layout = QHBoxLayout(filter_card)
        filter_layout.setContentsMargins(20, 14, 20, 14)
        filter_layout.setSpacing(12)
        filter_label = QLabel("Filtrar por categoria:")
        filter_label.setObjectName("sectionTitle")
        self._filter_combo = QComboBox()
        self._filter_combo.addItem("Todas as categorias", userData=None)
        for category in AuditCategory:
            self._filter_combo.addItem(category.value, userData=category.value)
        self._filter_combo.currentIndexChanged.connect(self._apply_filter)
        self._count_label = QLabel("Nenhuma auditoria executada.")
        self._count_label.setObjectName("sectionDescription")
        filter_layout.addWidget(filter_label)
        filter_layout.addWidget(self._filter_combo)
        filter_layout.addSpacing(18)
        filter_layout.addWidget(self._count_label)
        filter_layout.addStretch()
        layout.addWidget(filter_card)

        table_card = CardFrame()
        table_layout = QVBoxLayout(table_card)
        table_layout.setContentsMargins(20, 18, 20, 18)
        table_layout.setSpacing(12)
        table_layout.addWidget(
            SectionHeader(
                "Achados da auditoria",
                "Clique em uma linha para ver as evidencias completas e a recomendacao.",
            )
        )
        self._table = QTableWidget(0, 6)
        self._table.setObjectName("dataTable")
        self._table.setHorizontalHeaderLabels(
            ["Categoria", "Problema", "Severidade", "Status", "Score", "Evidencia resumida"]
        )
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self._table.verticalHeader().setVisible(False)
        self._table.horizontalHeader().setStretchLastSection(True)
        self._table.setAlternatingRowColors(True)
        self._table.currentItemChanged.connect(self._on_row_changed)
        table_layout.addWidget(self._table)

        self._detail_panel = QTextEdit()
        self._detail_panel.setObjectName("pageConsole")
        self._detail_panel.setReadOnly(True)
        self._detail_panel.setFixedHeight(160)
        table_layout.addWidget(self._detail_panel)
        layout.addWidget(table_card, 1)

    def set_action_enabled(self, action_key: str, enabled: bool) -> None:
        button = self._action_buttons.get(action_key)
        if button is not None:
            button.setEnabled(enabled)

    def populate_results(self, report: AuditReport, stamp: str) -> None:
        # Exibe apenas itens com problema; itens seguros ficam fora da grade.
        self._current_findings = [finding for finding in report.findings if finding.status != AuditStatus.SAFE]
        self._rebuild_table()
        issues_count = len(self._current_findings)
        self.score_metric.set_value(str(report.total_score))
        self.issues_metric.set_value(str(issues_count))
        self.status_metric.set_value(report.overall_status.value)
        self.stamp_metric.set_value(stamp)
        self._update_count_label()
        if issues_count == 0:
            self._detail_panel.setPlainText("Nenhum problema de seguranca foi encontrado nesta auditoria.")

    def clear_results(self) -> None:
        self._current_findings = []
        self._visible_row_to_finding = {}
        self._table.setRowCount(0)
        self._detail_panel.clear()
        self.score_metric.set_value("--")
        self.issues_metric.set_value("--")
        self.status_metric.set_value("--")
        self.stamp_metric.set_value("--")
        self._count_label.setText("Auditoria em andamento...")

    def start_progress(self) -> None:
        self._progress_bar.setValue(0)
        self._progress_percent.setText("0%")
        self._progress_phase.setText("Inicializando auditoria...")

    def set_progress(self, percent: int, phase: str | None = None) -> None:
        bounded = max(0, min(100, int(percent)))
        self._progress_bar.setValue(bounded)
        self._progress_percent.setText(f"{bounded}%")
        if phase:
            self._progress_phase.setText(phase)

    def finish_progress(self, interrupted: bool = False) -> None:
        if interrupted:
            current = self._progress_bar.value()
            self._progress_bar.setValue(max(0, min(99, current)))
            self._progress_percent.setText(f"{self._progress_bar.value()}%")
            self._progress_phase.setText("Auditoria interrompida pelo usuario.")
            return
        self._progress_bar.setValue(100)
        self._progress_percent.setText("100%")
        self._progress_phase.setText("Auditoria concluida.")

    def selected_finding(self) -> AuditFinding | None:
        """Retorna o achado atualmente selecionado na tabela."""
        current_row = self._table.currentRow()
        if current_row < 0:
            return None
        finding_index = self._visible_row_to_finding.get(current_row)
        if finding_index is None:
            return None
        return self._current_findings[finding_index]

    def _apply_filter(self) -> None:
        self._rebuild_table()
        self._update_count_label()
        self._detail_panel.clear()

    def _rebuild_table(self) -> None:
        self._table.setRowCount(0)
        self._visible_row_to_finding = {}
        selected_category = self._filter_combo.currentData()
        visible_row = 0
        for finding_index, finding in enumerate(self._current_findings):
            if selected_category is not None and finding.category.value != selected_category:
                continue
            self._table.insertRow(visible_row)
            self._visible_row_to_finding[visible_row] = finding_index
            category_item = QTableWidgetItem(finding.category.value)
            problem_item = QTableWidgetItem(finding.problem_name)
            severity_item = QTableWidgetItem(finding.severity.value)
            status_item = QTableWidgetItem(finding.status.value)
            score_item = QTableWidgetItem(str(finding.score))
            evidence_summary = finding.evidence[0] if finding.evidence else finding.details or "-"
            evidence_item = QTableWidgetItem(evidence_summary)
            severity_color = _SEVERITY_COLORS.get(finding.severity)
            if severity_color is not None:
                severity_item.setForeground(severity_color)
            status_color = _STATUS_COLORS.get(finding.status)
            if status_color is not None:
                status_item.setForeground(status_color)
            self._table.setItem(visible_row, 0, category_item)
            self._table.setItem(visible_row, 1, problem_item)
            self._table.setItem(visible_row, 2, severity_item)
            self._table.setItem(visible_row, 3, status_item)
            self._table.setItem(visible_row, 4, score_item)
            self._table.setItem(visible_row, 5, evidence_item)
            visible_row += 1

    def _update_count_label(self) -> None:
        total = len(self._current_findings)
        visible = self._table.rowCount()
        if total == 0:
            self._count_label.setText("Nenhum achado disponivel.")
            return
        if total == visible:
            self._count_label.setText(f"{total} achados no total.")
            return
        self._count_label.setText(f"Exibindo {visible} de {total} achados.")

    def _on_row_changed(self, current: QTableWidgetItem | None, previous: QTableWidgetItem | None) -> None:
        if current is None:
            return
        finding_index = self._visible_row_to_finding.get(current.row())
        if finding_index is None:
            return
        finding = self._current_findings[finding_index]
        lines = [
            f"Problema: {finding.problem_name}",
            f"Categoria: {finding.category.value} | Severidade: {finding.severity.value} | Status: {finding.status.value} | Score: {finding.score}",
            "",
        ]
        if finding.evidence:
            lines.append("Evidencias:")
            for evidence in finding.evidence:
                lines.append(f"- {evidence}")
            lines.append("")
        if finding.recommendation:
            lines.append(f"Recomendacao: {finding.recommendation}")
        if finding.details:
            lines.append(f"Detalhes: {finding.details}")
        self._detail_panel.setPlainText("\n".join(lines))