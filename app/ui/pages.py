"""Paginas principais usadas pela interface reorganizada do SentinelaPC."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QProgressBar,
    QScrollArea,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)
from PySide6.QtGui import QColor
from PySide6.QtWidgets import QAbstractItemView, QComboBox, QSizePolicy

from app.core.bootstrap import ApplicationContext
from app.data.history_models import HistoryEntry
from app.services.audit_models import AuditCategory, AuditFinding, AuditReport, AuditSeverity, AuditStatus
from app.services.quarantine_models import QuarantineItem
from app.ui.panels import ActionsPanel, ResultsPanel
from app.ui.widgets import ActionButton, CardFrame, MetricCard, SectionHeader


class DashboardPage(QWidget):
    """Dashboard compacto com foco principal no carrossel de modulos."""

    action_requested = Signal(str)
    real_time_protection_toggled = Signal()

    def __init__(self, context: ApplicationContext, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._compact_mode = False

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)

        # ── Faixa de status (topo) ──────────────────────────────────────────
        self.status_bar_card = CardFrame(elevated=True)
        self.status_bar_card.setObjectName("dashboardLeadCard")
        self.status_bar_card.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum)
        status_bar_layout = QHBoxLayout(self.status_bar_card)
        status_bar_layout.setContentsMargins(14, 10, 14, 10)
        status_bar_layout.setSpacing(10)
        status_bar_layout.setAlignment(Qt.AlignmentFlag.AlignVCenter)

        self._protection_chip = QPushButton()
        self._protection_chip.setCheckable(True)
        self._protection_chip.setCursor(Qt.CursorShape.PointingHandCursor)
        self._protection_chip.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self._protection_chip.setSizePolicy(QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Fixed)
        self._protection_chip.clicked.connect(lambda _checked: self.real_time_protection_toggled.emit())
        self.update_protection_ui_state(enabled=True)

        self._threats_chip = QLabel("Ameacas: 0")
        self._threats_chip.setObjectName("headerPill")
        self._threats_chip.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self._quarantine_chip = QLabel("Quarentena: 0")
        self._quarantine_chip.setObjectName("headerPill")
        self._quarantine_chip.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._monitor_chip = QLabel("Monitor: ativo")
        self._monitor_chip.setObjectName("headerPillAccent")
        self._monitor_chip.setAlignment(Qt.AlignmentFlag.AlignCenter)

        title_label = QLabel("SentinelaPC  ●  Painel principal")
        title_label.setObjectName("appKicker")

        status_bar_layout.addWidget(title_label)
        status_bar_layout.addStretch()
        status_bar_layout.addWidget(self._protection_chip)
        status_bar_layout.addWidget(self._threats_chip)
        status_bar_layout.addWidget(self._quarantine_chip)
        status_bar_layout.addWidget(self._monitor_chip)

        layout.addWidget(self.status_bar_card)

        # ── Carrossel de modulos ────────────────────────────────────────────
        self.actions_panel = ActionsPanel()
        self.actions_panel.set_carousel_prominent(True)
        self.actions_panel.action_requested.connect(self.action_requested.emit)

        # ── Painel de atividade (com scroll proprio) ────────────────────────
        self.activity_panel = ResultsPanel()
        self.activity_panel.set_compact(True)

        self._content_layout = QVBoxLayout()
        self._content_layout.setContentsMargins(0, 0, 0, 0)
        self._content_layout.setSpacing(8)
        self._content_layout.addWidget(self.actions_panel)
        self._content_layout.addWidget(self.activity_panel, 1)

        layout.addLayout(self._content_layout, 1)
        self._apply_compact_mode(True)

    def _apply_compact_mode(self, compact: bool) -> None:
        if compact == self._compact_mode:
            return
        self._compact_mode = compact

        # Mantem a barra responsiva ao conteudo para evitar corte em DPI alto.
        self.status_bar_card.setMinimumHeight(58 if compact else 66)
        self.status_bar_card.setMaximumHeight(16777215)
        self.actions_panel.set_carousel_prominent(True)
        self.activity_panel.set_compact(compact)

    def update_status_summary(self, threats: int = 0, quarantine: int = 0) -> None:
        """Atualiza os chips de ameacas e quarentena na faixa de status."""
        self._threats_chip.setText(f"Ameacas: {threats}")
        if threats > 0:
            self._threats_chip.setObjectName("headerPillAccent")
        else:
            self._threats_chip.setObjectName("headerPill")
        self._threats_chip.style().unpolish(self._threats_chip)
        self._threats_chip.style().polish(self._threats_chip)
        self._quarantine_chip.setText(f"Quarentena: {quarantine}")

    def update_protection_ui_state(self, *, enabled: bool) -> None:
        """Atualiza o chip clicavel de protecao em tempo real (ON/OFF)."""
        self._protection_chip.setChecked(enabled)
        self._protection_chip.setText("Protecao ativada" if enabled else "Protecao desativada")
        self._protection_chip.setObjectName(
            "realTimeProtectionToggleOn" if enabled else "realTimeProtectionToggleOff"
        )
        self._protection_chip.style().unpolish(self._protection_chip)
        self._protection_chip.style().polish(self._protection_chip)

    def update_monitor_status(self, label: str, *, alert: bool = False, inactive: bool = False) -> None:
        """Atualiza o chip de monitoramento de pre-execucao na faixa de status."""
        self._monitor_chip.setText(label)
        if inactive:
            new_obj = "headerPillMuted"
        else:
            new_obj = "headerPillAccent" if not alert else "headerPillWarn"
        self._monitor_chip.setObjectName(new_obj)
        self._monitor_chip.style().unpolish(self._monitor_chip)
        self._monitor_chip.style().polish(self._monitor_chip)

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

        # ── Scroll area interno ───────────────────────────────────────────────
        # Isola a altura desta página do QStackedWidget: sem scroll externo,
        # o sizeHint() de QStackedWidget seria o máximo de TODAS as páginas
        # (causando inflar a área disponível para o dashboard). Com scroll interno,
        # o sizeHint desta página é pequeno (tamanho do viewport), e ela rola
        # verticalmente quando o conteúdo excede a janela.
        _scroll = QScrollArea()
        _scroll.setObjectName("operationScrollArea")
        _scroll.setWidgetResizable(True)
        _scroll.setFrameShape(QFrame.Shape.NoFrame)
        _scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        _scroll.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        _content = QWidget()
        layout = QVBoxLayout(_content)
        layout.setContentsMargins(0, 4, 0, 12)
        layout.setSpacing(14)
        _scroll.setWidget(_content)
        _outer = QVBoxLayout(self)
        _outer.setContentsMargins(0, 0, 0, 0)
        _outer.setSpacing(0)
        _outer.addWidget(_scroll, 1)

        header_card = CardFrame(elevated=True)
        header_layout = QVBoxLayout(header_card)
        header_layout.setContentsMargins(24, 22, 24, 22)
        header_layout.setSpacing(6)

        eyebrow_label = QLabel(eyebrow)
        eyebrow_label.setObjectName("pageEyebrow")
        title_label = QLabel(title)
        title_label.setObjectName("pageTitleLarge")
        description_label = QLabel(description)
        description_label.setObjectName("pageSubtitle")
        description_label.setWordWrap(True)

        header_layout.addWidget(eyebrow_label)
        header_layout.addWidget(title_label)
        header_layout.addWidget(description_label)
        layout.addWidget(header_card)

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

        metrics_layout.addWidget(self.analyzed_metric, 1)
        metrics_layout.addWidget(self.suspicious_metric, 1)
        metrics_layout.addWidget(self.session_metric, 1)
        layout.addLayout(metrics_layout)

        progress_card = CardFrame()
        progress_card.setObjectName("featureCard")
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
        action_card.setObjectName("toolbarCard")
        action_layout = QGridLayout(action_card)
        action_layout.setContentsMargins(20, 18, 20, 18)
        action_layout.setHorizontalSpacing(10)
        action_layout.setVerticalSpacing(10)

        _max_cols = 3
        for _idx, (action_key, label) in enumerate(actions):
            button = ActionButton(action_key, label)
            button.setMinimumHeight(46)
            button.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
            button.triggered.connect(self.action_requested.emit)
            self._action_buttons[action_key] = button
            action_layout.addWidget(button, _idx // _max_cols, _idx % _max_cols)

        for _col in range(_max_cols):
            action_layout.setColumnStretch(_col, 1)
        layout.addWidget(action_card)

        navigation_card = CardFrame()
        navigation_card.setObjectName("toolbarCard")
        navigation_layout = QVBoxLayout(navigation_card)
        navigation_layout.setContentsMargins(20, 18, 20, 14)
        navigation_layout.setSpacing(10)
        navigation_layout.addWidget(
            SectionHeader(
                "Acesso rapido",
                "Volte ao painel principal ou navegue direto para as areas mais usadas sem depender apenas da barra lateral.",
            )
        )

        _nav_buttons_row = QHBoxLayout()
        _nav_buttons_row.setContentsMargins(0, 0, 0, 0)
        _nav_buttons_row.setSpacing(10)

        for action_key, label in (
            ("open_dashboard", "Pagina principal"),
            ("open_quarantine", "Quarentena"),
            ("open_history", "Historico"),
        ):
            button = ActionButton(action_key, label, style_variant="secondary")
            button.setMinimumHeight(44)
            button.triggered.connect(self.action_requested.emit)
            _nav_buttons_row.addWidget(button)

        _nav_buttons_row.addStretch()
        navigation_layout.addLayout(_nav_buttons_row)
        layout.addWidget(navigation_card)

        self.console_card = CardFrame()
        self.console_card.setObjectName("featureCard")
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
        # Altura mínima garante que o console seja visível após as seções superiores.
        # O scroll interno da página exibe scrollbar se o conteúdo total exceder
        # a altura da janela; o QTextEdit rola internamente para o seu conteúdo.
        self.console.setMinimumHeight(220)
        console_layout.addWidget(self.console)
        layout.addWidget(self.console_card)

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
            ("restore_all_quarantine", "Restaurar todos", "primary"),
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

        # ── Scroll area interno ───────────────────────────────────────────────
        # Mesma lógica da OperationPage: isola o sizeHint desta página do
        # QStackedWidget, evitando que ele infle o espaço do dashboard.
        _scroll = QScrollArea()
        _scroll.setObjectName("auditScrollArea")
        _scroll.setWidgetResizable(True)
        _scroll.setFrameShape(QFrame.Shape.NoFrame)
        _scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        _scroll.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        _content = QWidget()
        layout = QVBoxLayout(_content)
        layout.setContentsMargins(0, 4, 0, 12)
        layout.setSpacing(14)
        _scroll.setWidget(_content)
        _outer = QVBoxLayout(self)
        _outer.setContentsMargins(0, 0, 0, 0)
        _outer.setSpacing(0)
        _outer.addWidget(_scroll, 1)

        eyebrow = QLabel("Seguranca avancada do sistema")
        eyebrow.setObjectName("pageEyebrow")
        title = QLabel("Auditoria Avancada")
        title.setObjectName("pageTitleLarge")
        subtitle = QLabel(
            "Verificacao tecnica de configuracoes de seguranca, firewall, acesso remoto, privacidade e protecao de dados. "
            "Cada achado inclui evidencia e recomendacao. Selecione um ou mais itens para resolver apenas o que voce escolher."
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
            ("audit_resolve", "Resolver selecionados"),
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
        self._table.setMinimumHeight(160)
        self._table.setHorizontalHeaderLabels(
            ["Categoria", "Problema", "Severidade", "Status", "Score", "Evidencia resumida"]
        )
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._table.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self._table.verticalHeader().setVisible(False)
        self._table.horizontalHeader().setStretchLastSection(True)
        self._table.setAlternatingRowColors(True)
        self._table.itemSelectionChanged.connect(self._on_selection_changed)
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
        elif self._table.rowCount() > 0:
            self._table.selectRow(0)

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
        selected = self.selected_findings()
        if not selected:
            return None
        return selected[0]

    def selected_findings(self) -> list[AuditFinding]:
        """Retorna todos os achados selecionados atualmente na tabela filtrada."""
        selection_model = self._table.selectionModel()
        if selection_model is None:
            return []

        findings: list[AuditFinding] = []
        for model_index in selection_model.selectedRows():
            finding_index = self._visible_row_to_finding.get(model_index.row())
            if finding_index is None:
                continue
            findings.append(self._current_findings[finding_index])
        return findings

    def _apply_filter(self) -> None:
        self._rebuild_table()
        self._update_count_label()
        self._detail_panel.clear()
        if self._table.rowCount() > 0:
            self._table.selectRow(0)

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

    def _on_selection_changed(self) -> None:
        selected = self.selected_findings()
        if not selected:
            self._detail_panel.clear()
            return

        if len(selected) > 1:
            auto_count = sum(1 for finding in selected if finding.auto_resolvable and finding.resolver_key)
            manual_count = len(selected) - auto_count
            lines = [
                f"{len(selected)} achados selecionados.",
                f"Com correcao automatica suportada: {auto_count}",
                f"Com tratamento guiado/manual: {manual_count}",
                "",
                "Itens selecionados:",
            ]
            for finding in selected:
                mode = "Automatico" if finding.auto_resolvable and finding.resolver_key else "Guiado/manual"
                lines.append(
                    f"- {finding.problem_name} | categoria={finding.category.value} | severidade={finding.severity.value} | modo={mode}"
                )
            self._detail_panel.setPlainText("\n".join(lines))
            return

        finding = selected[0]
        lines = [
            f"Problema: {finding.problem_name}",
            f"Categoria: {finding.category.value} | Severidade: {finding.severity.value} | Status: {finding.status.value} | Score: {finding.score}",
            (
                f"Modo de tratamento: {'Correcao automatica suportada' if finding.auto_resolvable and finding.resolver_key else 'Tratamento guiado/manual'}"
            ),
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