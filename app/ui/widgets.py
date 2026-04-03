"""Widgets reutilizaveis usados pela interface principal."""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)


class CardFrame(QFrame):
    """Container visual padrao para blocos da interface."""

    def __init__(self, parent: QWidget | None = None, *, elevated: bool = False) -> None:
        super().__init__(parent)
        self.setObjectName("cardFrameElevated" if elevated else "cardFrame")
        self.setFrameShape(QFrame.Shape.NoFrame)


class SectionHeader(QWidget):
    """Cabecalho simples para padronizar titulos e descricoes."""

    def __init__(self, title: str, description: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(2)

        title_label = QLabel(title)
        title_label.setObjectName("sectionTitle")

        description_label = QLabel(description)
        description_label.setObjectName("sectionDescription")
        description_label.setWordWrap(True)

        layout.addWidget(title_label)
        layout.addWidget(description_label)


class MetricCard(CardFrame):
    """Card compacto para exibir indicadores resumidos."""

    def __init__(
        self,
        label: str,
        value: str,
        caption: str,
        parent: QWidget | None = None,
        *,
        icon: str = "",
    ) -> None:
        super().__init__(parent)
        self.value_label = QLabel(value)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(18, 16, 18, 16)
        outer.setSpacing(6)

        top = QHBoxLayout()
        top.setSpacing(8)

        if icon:
            icon_label = QLabel(icon)
            icon_label.setStyleSheet("font-size: 18px; color: #3b9eff; background: transparent;")
            top.addWidget(icon_label)

        label_widget = QLabel(label)
        label_widget.setObjectName("metricLabel")
        top.addWidget(label_widget)
        top.addStretch()

        self.value_label.setObjectName("metricValue")

        caption_widget = QLabel(caption)
        caption_widget.setObjectName("metricCaption")
        caption_widget.setWordWrap(True)

        outer.addLayout(top)
        outer.addWidget(self.value_label)
        outer.addWidget(caption_widget)
        outer.addStretch()

    def set_value(self, value: str) -> None:
        """Atualiza o valor exibido sem alterar a estrutura do card."""
        self.value_label.setText(value)


# Mapa de icones unicode por action_key
_ACTION_ICONS: dict[str, str] = {
    "quick_scan":        "⚡",
    "full_scan":         "🔍",
    "pause_scan":        "⏸",
    "stop_scan":         "⏹",
    "process_scan":      "⚙",
    "startup_scan":      "🚀",
    "open_audit":        "🛡",
    "open_history":      "📋",
    "quarantine_file":   "🔒",
    "diagnostics":       "💊",
    "open_quarantine":   "🗂",
    "generate_report":   "📄",
    "browser_scan":      "🌐",
    "email_scan_file":   "✉",
    "email_scan_folder": "📁",
}


class ActionButton(QPushButton):
    """Botao padronizado para as principais operacoes do painel."""

    triggered = Signal(str)

    def __init__(
        self,
        action_key: str,
        label: str,
        parent: QWidget | None = None,
        *,
        style_variant: str = "primary",
        tile: bool = False,
    ) -> None:
        super().__init__(parent)
        self.action_key = action_key
        self.tile_mode = tile

        if tile:
            icon = _ACTION_ICONS.get(action_key, "▶")
            self.setText(f"{icon}\n{label}")
            self.setObjectName("actionTile")
            self.setMinimumSize(110, 90)
            self.setMaximumSize(200, 110)
        else:
            self.setText(label)
            self.setObjectName(
                "secondaryActionButton" if style_variant == "secondary" else "primaryActionButton"
            )
            self.setMinimumHeight(46)

        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.clicked.connect(self._emit_triggered)

    def _emit_triggered(self) -> None:
        """Expone um sinal de alto nivel para a janela principal decidir a acao."""
        self.triggered.emit(self.action_key)
