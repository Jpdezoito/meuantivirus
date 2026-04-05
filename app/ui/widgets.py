"""Widgets reutilizaveis usados pela interface principal."""

from __future__ import annotations

from PySide6.QtCore import Qt, QSize, Signal
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QSizePolicy,
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
        super().__init__(parent, elevated=True)
        self.value_label = QLabel(value)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(20, 18, 20, 18)
        outer.setSpacing(10)

        top = QHBoxLayout()
        top.setSpacing(10)

        if icon:
            icon_label = QLabel(icon)
            icon_label.setObjectName("metricIcon")
            icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            icon_label.setFixedSize(34, 34)
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
    TILE_WIDE_MIN_WIDTH = 138
    TILE_WIDE_MIN_HEIGHT = 108
    TILE_WIDE_MAX_HEIGHT = 132
    TILE_COMPACT_SIZE = 188

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
            self.setObjectName("actionTile")
            self.setMinimumSize(self.TILE_WIDE_MIN_WIDTH, self.TILE_WIDE_MIN_HEIGHT)
            self.setMinimumHeight(self.TILE_WIDE_MIN_HEIGHT)
            self.setMaximumHeight(self.TILE_WIDE_MAX_HEIGHT)
            self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        else:
            self.setObjectName(
                "secondaryActionButton" if style_variant == "secondary" else "primaryActionButton"
            )
            self.setMinimumHeight(54)

        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.clicked.connect(self._emit_triggered)
        self.update_action(action_key, label)

    def update_action(self, action_key: str, label: str) -> None:
        """Atualiza identificador, texto e icone sem recriar o botao."""
        self.action_key = action_key
        self.setText(label)

        if self.tile_mode:
            icon_name = ICON_MAP.get(action_key, "dashboard")
            btn_icon = get_icon(icon_name, size=40, color="#f7fbff")
            if btn_icon:
                self.setIcon(btn_icon)
                self.setIconSize(QSize(40, 40))
            return

        icon_name = ICON_MAP.get(action_key, "dashboard")
        btn_icon = get_icon(icon_name, size=20, color="#f7fbff")
        if btn_icon:
            self.setIcon(btn_icon)
            self.setIconSize(QSize(20, 20))

    def set_tile_compact(self, compact: bool, *, size: int | None = None) -> None:
        """Alterna o tile entre formato amplo (grid) e quadrado (carrossel)."""
        if not self.tile_mode:
            return

        if compact:
            compact_size = size if size is not None else self.TILE_COMPACT_SIZE
            self.setMinimumSize(compact_size, compact_size)
            self.setMaximumSize(compact_size, compact_size)
            self.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
            self.setIconSize(QSize(36, 36))
            return

        self.setMinimumSize(self.TILE_WIDE_MIN_WIDTH, self.TILE_WIDE_MIN_HEIGHT)
        self.setMaximumWidth(16777215)
        self.setMaximumHeight(self.TILE_WIDE_MAX_HEIGHT)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.setIconSize(QSize(40, 40))

    def _emit_triggered(self) -> None:
        """Expone um sinal de alto nivel para a janela principal decidir a acao."""
        self.triggered.emit(self.action_key)
