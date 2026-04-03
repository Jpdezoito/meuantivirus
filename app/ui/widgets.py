"""Widgets reutilizaveis usados pela interface principal."""

from __future__ import annotations

from PySide6.QtCore import Qt, QSize, Signal
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from app.ui.icons import get_icon, ICON_MAP


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


class ActionButton(QPushButton):
    """Botao padronizado para as principais operacoes do painel — com ícones Font Awesome."""

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
            # ActionTile com ícone grande (48px)
            self.setText(label)
            self.setObjectName("actionTile")
            self.setMinimumSize(140, 120)    # Era 110x90
            self.setMaximumSize(180, 140)
            
            # Adicionar ícone Font Awesome 48px
            icon_name = ICON_MAP.get(action_key, "dashboard")
            btn_icon = get_icon(icon_name, size=48, color="#3b9eff")
            if btn_icon:
                self.setIcon(btn_icon)
                self.setIconSize(QSize(48, 48))
        else:
            # Botão inline com ícone pequeno (20px)
            self.setText(label)
            self.setObjectName(
                "secondaryActionButton" if style_variant == "secondary" else "primaryActionButton"
            )
            self.setMinimumHeight(52)    # Era 46
            
            # Adicionar ícone Font Awesome 20px
            icon_name = ICON_MAP.get(action_key, "dashboard")
            color = "white" if style_variant == "primary" else "#8ba3bb"
            btn_icon = get_icon(icon_name, size=20, color=color)
            if btn_icon:
                self.setIcon(btn_icon)
                self.setIconSize(QSize(20, 20))

        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.clicked.connect(self._emit_triggered)

    def _emit_triggered(self) -> None:
        """Expone um sinal de alto nivel para a janela principal decidir a acao."""
        self.triggered.emit(self.action_key)
