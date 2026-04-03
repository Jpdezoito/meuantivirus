"""Paineis visuais que compoem a janela principal do SentinelaPC."""

from __future__ import annotations

from collections.abc import Iterable

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from app.core.bootstrap import ApplicationContext
from app.ui.widgets import ActionButton, CardFrame, MetricCard, SectionHeader


class HeaderPanel(QWidget):
    """Cabecalho superior com identidade visual da aplicacao."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("topHeader")

        layout = QHBoxLayout(self)
        layout.setContentsMargins(28, 16, 28, 16)
        layout.setSpacing(0)

        title = QLabel("SentinelaPC")
        title.setObjectName("appTitle")

        subtitle = QLabel("Central de seguranca e diagnostico do sistema Windows")
        subtitle.setObjectName("appSubtitle")
        subtitle.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)

        layout.addWidget(title)
        layout.addStretch()
        layout.addWidget(subtitle)


class HeroStatusCard(QFrame):
    """Card hero que mostra o status geral de protecao do sistema."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("heroCard")
        self.setFixedHeight(100)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(28, 16, 28, 16)
        layout.setSpacing(20)

        self._icon_label = QLabel("OK")
        self._icon_label.setStyleSheet("font-size: 24px; background: transparent;")
        self._icon_label.setFixedWidth(44)
        self._icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        text_col = QVBoxLayout()
        text_col.setSpacing(4)
        text_col.setContentsMargins(0, 0, 0, 0)

        self._title_label = QLabel("Seu PC esta protegido")
        self._title_label.setObjectName("heroStatusTitle")

        self._sub_label = QLabel("Nenhuma ameaca detectada nas ultimas verificacoes.")
        self._sub_label.setObjectName("heroStatusSubtitle")

        text_col.addWidget(self._title_label)
        text_col.addWidget(self._sub_label)

        layout.addWidget(self._icon_label, 0, Qt.AlignmentFlag.AlignVCenter)
        layout.addLayout(text_col, 1)

    def set_status(self, title: str, subtitle: str, level: str = "ok") -> None:
        """Atualiza o hero com o novo status (level: ok|warn|danger)."""
        icons = {"ok": "OK", "warn": "!", "danger": "X"}
        obj_names = {
            "ok":     "heroStatusTitle",
            "warn":   "heroStatusTitleWarn",
            "danger": "heroStatusTitleDanger",
        }
        self._icon_label.setText(icons.get(level, "OK"))
        self._title_label.setObjectName(obj_names.get(level, "heroStatusTitle"))
        self._title_label.style().unpolish(self._title_label)
        self._title_label.style().polish(self._title_label)
        self._title_label.setText(title)
        self._sub_label.setText(subtitle)


class SystemStatusPanel(CardFrame):
    """Indicadores rapidos de ambiente (protecao, banco, logs)."""

    def __init__(self, context: ApplicationContext, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.context = context

        layout = QHBoxLayout(self)
        layout.setContentsMargins(18, 16, 18, 16)
        layout.setSpacing(12)

        self.protection_metric = MetricCard("PROTECAO", "Pronto", "Aguardando verificacoes", icon="S")
        self.database_metric   = MetricCard("BANCO",    "SQLite", context.paths.database_file.name, icon="D")
        self.logs_metric       = MetricCard("LOGS",     "Ativo",  context.paths.daily_log_file.name, icon="L")

        for m in (self.protection_metric, self.database_metric, self.logs_metric):
            layout.addWidget(m, 1)


class ActionsPanel(CardFrame):
    """Grid de tiles de acao para os modulos principais."""

    action_requested = Signal(str)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._buttons: dict[str, ActionButton] = {}

        root = QVBoxLayout(self)
        root.setContentsMargins(18, 16, 18, 16)
        root.setSpacing(12)

        header = QLabel("Acoes rapidas")
        header.setObjectName("sectionTitle")
        root.addWidget(header)

        grid = QGridLayout()
        grid.setHorizontalSpacing(8)
        grid.setVerticalSpacing(8)

        COLS = 5
        buttons = [
            ("quick_scan",      "Verificar\narquivos"),
            ("full_scan",       "Scan\ncompleto"),
            ("process_scan",    "Processos"),
            ("startup_scan",    "Inicializacao"),
            ("open_audit",      "Auditoria"),
            ("diagnostics",     "Diagnostico"),
            ("quarantine_file", "Quarentena"),
            ("generate_report", "Relatorio"),
            ("open_history",    "Historico"),
            ("open_quarantine", "Ver\nquarentena"),
        ]

        for idx, (key, label) in enumerate(buttons):
            btn = ActionButton(key, label, tile=True)
            btn.triggered.connect(self.action_requested.emit)
            self._buttons[key] = btn
            grid.addWidget(btn, idx // COLS, idx % COLS)

        for col in range(COLS):
            grid.setColumnStretch(col, 1)

        root.addLayout(grid)

    def set_action_enabled(self, action_key: str, enabled: bool) -> None:
        """Controla o estado de um botao especifico sem alterar os demais."""
        btn = self._buttons.get(action_key)
        if btn is not None:
            btn.setEnabled(enabled)


class ResultsPanel(CardFrame):
    """Console visual para logs de interface e resultados da sessao."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.console = QTextEdit()

        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 16, 18, 16)
        layout.setSpacing(10)

        header = QLabel("Atividade da sessao")
        header.setObjectName("sectionTitle")
        layout.addWidget(header)

        self.console.setObjectName("resultsConsole")
        self.console.setReadOnly(True)
        self.console.setMinimumHeight(160)
        layout.addWidget(self.console)

    def append_lines(self, lines: Iterable[str]) -> None:
        """Adiciona varias linhas ao console mantendo o historico visivel."""
        for line in lines:
            self.console.append(line)

    def clear(self) -> None:
        """Limpa o console."""
        self.console.clear()


class FooterStatusPanel:
    """Mensagem padrao da barra inferior."""

    @staticmethod
    def default_message() -> str:
        """Retorna a mensagem padrao mostrada ao abrir a aplicacao."""
        return "Pronto -- execute uma verificacao para comecar."