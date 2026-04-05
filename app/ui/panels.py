"""Paineis visuais que compoem a janela principal do SentinelaPC."""

from __future__ import annotations

from collections.abc import Iterable

from PySide6.QtCore import QEasingCurve, QParallelAnimationGroup, QPropertyAnimation, QRect, Qt, Signal
from PySide6.QtGui import QKeyEvent, QResizeEvent
from PySide6.QtWidgets import (
    QFrame,
    QGraphicsOpacityEffect,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from app.core.bootstrap import ApplicationContext
from app.ui.widgets import ActionButton, CardFrame, MetricCard, SectionHeader


class HeaderPanel(QWidget):
    """Cabecalho superior com identidade visual da aplicacao."""

    def __init__(self, app_name: str, version: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("topHeader")

        layout = QHBoxLayout(self)
        layout.setContentsMargins(26, 20, 26, 20)
        layout.setSpacing(18)

        left_column = QVBoxLayout()
        left_column.setContentsMargins(0, 0, 0, 0)
        left_column.setSpacing(4)

        kicker = QLabel("DESKTOP SECURITY CENTER")
        kicker.setObjectName("appKicker")

        title = QLabel(app_name)
        title.setObjectName("appTitle")

        subtitle = QLabel("Protecao, diagnostico e resposta operacional em uma interface unificada para Windows")
        subtitle.setObjectName("appSubtitle")
        subtitle.setWordWrap(True)

        left_column.addWidget(kicker)
        left_column.addWidget(title)
        left_column.addWidget(subtitle)

        meta_group = QWidget()
        meta_group.setObjectName("headerMetaGroup")
        meta_layout = QHBoxLayout(meta_group)
        meta_layout.setContentsMargins(0, 0, 0, 0)
        meta_layout.setSpacing(10)

        desktop_chip = QLabel("Desktop Windows")
        desktop_chip.setObjectName("headerPill")
        version_chip = QLabel(f"Versao {version}")
        version_chip.setObjectName("headerPill")

        meta_layout.addWidget(desktop_chip)
        meta_layout.addWidget(version_chip)

        layout.addLayout(left_column, 1)
        layout.addStretch()
        layout.addWidget(meta_group, 0, Qt.AlignmentFlag.AlignTop)


class HeroStatusCard(QFrame):
    """Card hero que mostra o status geral de protecao do sistema."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("heroCard")
        self.setMinimumHeight(182)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(28, 24, 28, 24)
        layout.setSpacing(22)

        self._icon_label = QLabel("OK")
        self._icon_label.setObjectName("heroBadge")
        self._icon_label.setFixedSize(56, 56)
        self._icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        text_col = QVBoxLayout()
        text_col.setSpacing(8)
        text_col.setContentsMargins(0, 0, 0, 0)

        eyebrow_label = QLabel("STATUS CENTRAL")
        eyebrow_label.setObjectName("pageEyebrow")

        self._title_label = QLabel("Seu PC esta protegido")
        self._title_label.setObjectName("heroStatusTitle")

        self._sub_label = QLabel("Nenhuma ameaca detectada nas ultimas verificacoes.")
        self._sub_label.setObjectName("heroStatusSubtitle")
        self._sub_label.setWordWrap(True)

        self._footnote_label = QLabel(
            "Use os blocos de verificacao abaixo para iniciar scans locais, auditorias e diagnosticos sem sair do painel principal."
        )
        self._footnote_label.setObjectName("sectionDescription")
        self._footnote_label.setWordWrap(True)

        text_col.addWidget(eyebrow_label)
        text_col.addWidget(self._title_label)
        text_col.addWidget(self._sub_label)
        text_col.addWidget(self._footnote_label)

        meta_col = QVBoxLayout()
        meta_col.setContentsMargins(0, 0, 0, 0)
        meta_col.setSpacing(10)

        self._meta_title = QLabel("Visao rapida")
        self._meta_title.setObjectName("heroMetaLabel")

        self._meta_values = QWidget()
        self._meta_values.setObjectName("heroMetaPanel")
        meta_values_layout = QVBoxLayout(self._meta_values)
        meta_values_layout.setContentsMargins(16, 14, 16, 14)
        meta_values_layout.setSpacing(8)

        for label in (
            "Escaneamento sob demanda pronto",
            "Quarentena e historico integrados",
            "Relatorios TXT e HTML disponiveis",
        ):
            item = QLabel(label)
            item.setObjectName("heroMetaValue")
            meta_values_layout.addWidget(item)

        meta_col.addWidget(self._meta_title)
        meta_col.addWidget(self._meta_values)
        meta_col.addStretch()

        layout.addWidget(self._icon_label, 0, Qt.AlignmentFlag.AlignVCenter)
        layout.addLayout(text_col, 1)
        layout.addLayout(meta_col)

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

    def set_compact(self, compact: bool) -> None:
        """Reduz elementos secundarios do hero para priorizar o carrossel em telas menores."""
        self._footnote_label.setVisible(not compact)
        self._meta_title.setVisible(not compact)
        self._meta_values.setVisible(not compact)
        if compact:
            self.setMinimumHeight(136)
            self.setMaximumHeight(170)
            return
        self.setMinimumHeight(182)
        self.setMaximumHeight(16777215)


class SystemStatusPanel(CardFrame):
    """Indicadores rapidos de ambiente (protecao, banco, logs)."""

    def __init__(self, context: ApplicationContext, parent: QWidget | None = None) -> None:
        super().__init__(parent, elevated=True)
        self.context = context
        self._metric_cards: list[MetricCard] = []
        self._metric_columns = 0

        root = QVBoxLayout(self)
        root.setContentsMargins(20, 18, 20, 18)
        root.setSpacing(14)

        root.addWidget(
            SectionHeader(
                "Operacao local pronta",
                "Base, logs e armazenamento local ja preparados para iniciar verificacoes com seguranca.",
            )
        )

        self._metrics_grid = QGridLayout()
        self._metrics_grid.setContentsMargins(0, 0, 0, 0)
        self._metrics_grid.setHorizontalSpacing(12)
        self._metrics_grid.setVerticalSpacing(12)

        self.protection_metric = MetricCard("PROTECAO", "Pronto", "Aguardando verificacoes", icon="S")
        self.database_metric   = MetricCard("BANCO",    "SQLite", context.paths.database_file.name, icon="D")
        self.logs_metric       = MetricCard("LOGS",     "Ativo",  context.paths.daily_log_file.name, icon="L")
        self._metric_cards = [self.protection_metric, self.database_metric, self.logs_metric]

        root.addLayout(self._metrics_grid)
        self._reflow_metrics(self._resolve_metric_columns())

    def resizeEvent(self, event: QResizeEvent) -> None:
        """Adapta os cards para 3/2/1 colunas conforme a largura disponivel."""
        super().resizeEvent(event)
        self._reflow_metrics(self._resolve_metric_columns())

    def _resolve_metric_columns(self) -> int:
        width = self.width()
        if width >= 680:
            return 2
        return 1

    def _reflow_metrics(self, columns: int) -> None:
        if columns == self._metric_columns:
            return

        self._metric_columns = columns

        while self._metrics_grid.count():
            item = self._metrics_grid.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.setParent(self)

        for idx, card in enumerate(self._metric_cards):
            row = idx // columns
            col = idx % columns
            self._metrics_grid.addWidget(card, row, col)

        for col in range(3):
            self._metrics_grid.setColumnStretch(col, 1 if col < columns else 0)

    def set_compact(self, compact: bool) -> None:
        """Reduz altura para caber melhor em janelas pequenas."""
        self.setMaximumHeight(178 if compact else 16777215)


class ActionsPanel(CardFrame):
    """Carrossel de modulos com 3 cards visiveis: lateral | central (destaque) | lateral."""

    action_requested = Signal(str)
    ANIMATION_DURATION_MS = 340
    SIDE_OPACITY = 0.68
    CENTER_OPACITY = 1.0

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent, elevated=True)
        self.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        self._carousel_mode = True
        self._animating = False
        self._active_animation: QParallelAnimationGroup | None = None

        self._carousel_index = 0
        self._size_center = 128
        self._size_side = 100
        self.setMaximumHeight(220)

        self._actions: list[tuple[str, str]] = [
            ("quick_scan", "Arquivos\nsuspeitos"),
            ("full_scan", "Verificacao\ncompleta"),
            ("process_scan", "Processos\nativos"),
            ("startup_scan", "Itens de\ninicializacao"),
            ("open_audit", "Auditoria\navancada"),
            ("diagnostics", "Diagnostico\ndo sistema"),
            ("open_quarantine", "Central de\nquarentena"),
            ("generate_report", "Gerar\nrelatorios"),
            ("open_history", "Historico\nda sessao"),
        ]
        self._enabled_by_key = {key: True for key, _ in self._actions}

        root = QVBoxLayout(self)
        root.setContentsMargins(14, 10, 14, 10)
        root.setSpacing(6)

        self._carousel_info = QLabel()
        self._carousel_info.setObjectName("carouselInfoLabel")
        self._carousel_info.setAlignment(Qt.AlignmentFlag.AlignCenter)
        root.addWidget(self._carousel_info)

        nav_row = QHBoxLayout()
        nav_row.setContentsMargins(0, 0, 0, 0)
        nav_row.setSpacing(8)

        self._prev_button = QPushButton("<")
        self._prev_button.setObjectName("carouselArrowButton")
        self._prev_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self._prev_button.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self._prev_button.clicked.connect(self._show_previous_action)

        self._next_button = QPushButton(">")
        self._next_button.setObjectName("carouselArrowButton")
        self._next_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self._next_button.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self._next_button.clicked.connect(self._show_next_action)

        self._carousel_stage = QWidget()
        self._carousel_stage.setObjectName("carouselStage")
        self._carousel_stage.setMinimumHeight(168)
        self._carousel_stage.setMinimumWidth(420)

        nav_row.addWidget(self._prev_button, 0, Qt.AlignmentFlag.AlignVCenter)
        nav_row.addWidget(self._carousel_stage, 1)
        nav_row.addWidget(self._next_button, 0, Qt.AlignmentFlag.AlignVCenter)

        root.addLayout(nav_row)
        self._left_card = self._build_carousel_card()
        self._center_card = self._build_carousel_card()
        self._right_card = self._build_carousel_card()
        self._buffer_card = self._build_carousel_card()

        self._sync_carousel_view(initial=True)

    def resizeEvent(self, event: QResizeEvent) -> None:
        super().resizeEvent(event)
        if not self._animating:
            self._sync_carousel_view(initial=True)

    def _build_carousel_card(self) -> ActionButton:
        button = ActionButton("quick_scan", "Arquivos\nsuspeitos", self._carousel_stage, tile=True)
        button.triggered.connect(self.action_requested.emit)
        effect = QGraphicsOpacityEffect(button)
        effect.setOpacity(self.SIDE_OPACITY)
        button.setGraphicsEffect(effect)
        button.hide()
        return button

    def _sync_carousel_view(self, *, initial: bool = False) -> None:
        n = len(self._actions)
        if n == 0:
            return

        self._carousel_index %= n
        center_idx = self._carousel_index
        left_idx = (center_idx - 1) % n if n >= 2 else None
        right_idx = (center_idx + 1) % n if n >= 3 else None

        if left_idx is not None:
            self._prepare_card(self._left_card, left_idx, role="side")
        else:
            self._left_card.hide()

        self._prepare_card(self._center_card, center_idx, role="center")

        if right_idx is not None:
            self._prepare_card(self._right_card, right_idx, role="side")
        else:
            self._right_card.hide()

        self._buffer_card.hide()
        self._apply_static_geometries(n)
        if initial:
            self._update_info_label()

    def _prepare_card(self, button: ActionButton, index: int, *, role: str) -> None:
        key, label = self._actions[index]
        size = self._effective_sizes()[0 if role == "center" else 1]
        button.update_action(key, label)
        button.set_tile_compact(True, size=size)
        button.setEnabled(self._enabled_by_key.get(key, True))
        button.setObjectName("actionTileCenter" if role == "center" else "actionTileSide")
        button.style().unpolish(button)
        button.style().polish(button)
        button.show()
        button.raise_()
        if role == "center":
            button.setIconSize(button.iconSize().expandedTo(button.iconSize()))

    def _apply_static_geometries(self, n: int) -> None:
        rects = self._target_rects()
        if n == 1:
            self._set_card_state(self._center_card, rects["center"], self.CENTER_OPACITY, raise_card=True)
            self._left_card.hide()
            self._right_card.hide()
            return

        self._set_card_state(self._left_card, rects["left"], self.SIDE_OPACITY)
        self._set_card_state(self._center_card, rects["center"], self.CENTER_OPACITY, raise_card=True)
        if n == 2:
            self._right_card.hide()
            return
        self._set_card_state(self._right_card, rects["right"], self.SIDE_OPACITY)

    def _set_card_state(self, button: ActionButton, rect: QRect, opacity: float, *, raise_card: bool = False) -> None:
        button.setGeometry(rect)
        effect = self._ensure_opacity_effect(button)
        effect.setOpacity(opacity)
        if raise_card:
            button.raise_()

    def _target_rects(self) -> dict[str, QRect]:
        stage_rect = self._carousel_stage.contentsRect()
        width = max(420, stage_rect.width())
        height = max(150, stage_rect.height())
        center_size, side_size = self._effective_sizes(width, height)

        center_x = (width - center_size) // 2
        center_y = max(2, (height - center_size) // 2 - 2)

        gap = max(14, (width - center_size - (2 * side_size)) // 4)
        left_x = max(6, gap)
        right_x = min(width - side_size - 6, width - gap - side_size)
        side_y = min(height - side_size - 4, center_y + max(10, (center_size - side_size) // 2))

        return {
            "left": QRect(left_x, side_y, side_size, side_size),
            "center": QRect(center_x, center_y, center_size, center_size),
            "right": QRect(right_x, side_y, side_size, side_size),
            "off_left": QRect(-side_size - 30, side_y, side_size, side_size),
            "off_right": QRect(width + 30, side_y, side_size, side_size),
        }

    def _effective_sizes(self, width: int | None = None, height: int | None = None) -> tuple[int, int]:
        stage_rect = self._carousel_stage.contentsRect()
        width = width if width is not None else max(420, stage_rect.width())
        height = height if height is not None else max(150, stage_rect.height())

        center = min(self._size_center, max(104, int(width * 0.28)), max(104, height - 16))
        side = min(self._size_side, max(84, int(center * 0.78)))
        return center, side

    def _update_info_label(self) -> None:
        if not self._actions:
            self._carousel_info.clear()
            return
        _, label = self._actions[self._carousel_index % len(self._actions)]
        title = label.replace("\n", " ")
        self._carousel_info.setText(f"Modulo {self._carousel_index + 1}/{len(self._actions)} - {title}")

    def _ensure_opacity_effect(self, button: ActionButton) -> QGraphicsOpacityEffect:
        effect = button.graphicsEffect()
        if isinstance(effect, QGraphicsOpacityEffect):
            return effect
        created = QGraphicsOpacityEffect(button)
        button.setGraphicsEffect(created)
        return created

    def _animate_widget(self, group: QParallelAnimationGroup, button: ActionButton, end_rect: QRect, end_opacity: float) -> None:
        geometry_anim = QPropertyAnimation(button, b"geometry", self)
        geometry_anim.setDuration(self.ANIMATION_DURATION_MS)
        geometry_anim.setEasingCurve(QEasingCurve.Type.InOutCubic)
        geometry_anim.setStartValue(button.geometry())
        geometry_anim.setEndValue(end_rect)
        group.addAnimation(geometry_anim)

        effect = self._ensure_opacity_effect(button)
        opacity_anim = QPropertyAnimation(effect, b"opacity", self)
        opacity_anim.setDuration(self.ANIMATION_DURATION_MS)
        opacity_anim.setEasingCurve(QEasingCurve.Type.InOutCubic)
        opacity_anim.setStartValue(effect.opacity())
        opacity_anim.setEndValue(end_opacity)
        group.addAnimation(opacity_anim)

    def _animate_to_index(self, new_index: int, *, direction: int) -> None:
        n = len(self._actions)
        if n <= 1 or self._animating:
            return

        rects = self._target_rects()
        group = QParallelAnimationGroup(self)
        self._animating = True
        self._active_animation = group

        if n == 2:
            self._prepare_card(self._left_card, (new_index - 1) % n, role="side")
            self._prepare_card(self._center_card, new_index, role="center")
            self._animate_widget(group, self._left_card, rects["left"], self.SIDE_OPACITY)
            self._animate_widget(group, self._center_card, rects["center"], self.CENTER_OPACITY)

            def _finish_two() -> None:
                self._carousel_index = new_index
                self._sync_carousel_view(initial=True)
                self._animating = False
                self._active_animation = None

            group.finished.connect(_finish_two)
            self._update_info_label_for(new_index)
            group.start()
            return

        old_left = self._left_card
        old_center = self._center_card
        old_right = self._right_card
        incoming = self._buffer_card

        if direction > 0:
            new_right_idx = (new_index + 1) % n
            self._prepare_card(incoming, new_right_idx, role="side")
            self._set_card_state(incoming, rects["off_right"], 0.0)

            self._prepare_card(old_center, self._carousel_index, role="side")
            self._prepare_card(old_right, (self._carousel_index + 1) % n, role="center")

            self._animate_widget(group, old_left, rects["off_left"], 0.0)
            self._animate_widget(group, old_center, rects["left"], self.SIDE_OPACITY)
            self._animate_widget(group, old_right, rects["center"], self.CENTER_OPACITY)
            self._animate_widget(group, incoming, rects["right"], self.SIDE_OPACITY)

            def _finish_forward() -> None:
                old_left.hide()
                self._left_card = old_center
                self._center_card = old_right
                self._right_card = incoming
                self._buffer_card = old_left
                self._carousel_index = new_index
                self._sync_carousel_view(initial=True)
                self._animating = False
                self._active_animation = None

            group.finished.connect(_finish_forward)
        else:
            new_left_idx = (new_index - 1) % n
            self._prepare_card(incoming, new_left_idx, role="side")
            self._set_card_state(incoming, rects["off_left"], 0.0)

            self._prepare_card(old_left, (self._carousel_index - 1) % n, role="center")
            self._prepare_card(old_center, self._carousel_index, role="side")

            self._animate_widget(group, old_right, rects["off_right"], 0.0)
            self._animate_widget(group, old_center, rects["right"], self.SIDE_OPACITY)
            self._animate_widget(group, old_left, rects["center"], self.CENTER_OPACITY)
            self._animate_widget(group, incoming, rects["left"], self.SIDE_OPACITY)

            def _finish_backward() -> None:
                old_right.hide()
                self._left_card = incoming
                self._center_card = old_left
                self._right_card = old_center
                self._buffer_card = old_right
                self._carousel_index = new_index
                self._sync_carousel_view(initial=True)
                self._animating = False
                self._active_animation = None

            group.finished.connect(_finish_backward)

        self._update_info_label_for(new_index)
        group.start()

    def _update_info_label_for(self, index: int) -> None:
        _, label = self._actions[index % len(self._actions)]
        title = label.replace("\n", " ")
        self._carousel_info.setText(f"Modulo {index + 1}/{len(self._actions)} - {title}")

    def _show_previous_action(self) -> None:
        if not self._actions:
            return
        self._animate_to_index((self._carousel_index - 1) % len(self._actions), direction=-1)

    def _show_next_action(self) -> None:
        if not self._actions:
            return
        self._animate_to_index((self._carousel_index + 1) % len(self._actions), direction=1)

    def keyPressEvent(self, event: QKeyEvent) -> None:
        if self._carousel_mode and event.key() == Qt.Key.Key_Left:
            self._show_previous_action()
            event.accept()
            return
        if self._carousel_mode and event.key() == Qt.Key.Key_Right:
            self._show_next_action()
            event.accept()
            return
        super().keyPressEvent(event)

    def focus_carousel(self) -> None:
        self.setFocus(Qt.FocusReason.ActiveWindowFocusReason)

    def set_carousel_prominent(self, prominent: bool) -> None:
        new_center = 128 if prominent else 116
        new_side = 100 if prominent else 88
        if new_center == self._size_center and new_side == self._size_side:
            return
        self._size_center = new_center
        self._size_side = new_side
        self.setMaximumHeight(220 if prominent else 196)
        self._sync_carousel_view(initial=True)

    def set_action_enabled(self, action_key: str, enabled: bool) -> None:
        self._enabled_by_key[action_key] = enabled
        n = len(self._actions)
        if n == 0:
            return
        center_idx = self._carousel_index % n
        visible_indices: set[int] = {center_idx}
        if n >= 2:
            visible_indices.add((center_idx - 1) % n)
        if n >= 3:
            visible_indices.add((center_idx + 1) % n)
        for idx in visible_indices:
            if self._actions[idx][0] == action_key:
                self._sync_carousel_view(initial=True)
                return


class ResultsPanel(CardFrame):
    """Console visual para logs de interface e resultados da sessao."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent, elevated=True)
        self.console = QTextEdit()

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 18, 20, 18)
        layout.setSpacing(12)

        layout.addWidget(
            SectionHeader(
                "Atividade da sessao",
                "Timeline operacional com inicializacao, acoes disparadas e resultados recebidos pelos modulos do desktop.",
            )
        )

        self.console.setObjectName("resultsConsole")
        self.console.setReadOnly(True)
        self.console.setMinimumHeight(220)
        layout.addWidget(self.console)

    def append_lines(self, lines: Iterable[str]) -> None:
        for line in lines:
            self.console.append(line)

    def clear(self) -> None:
        self.console.clear()

    def set_compact(self, compact: bool) -> None:
        from PySide6.QtCore import Qt as _Qt

        self.console.setMinimumHeight(90 if compact else 200)
        self.setMaximumHeight(16777215)
        self.console.setVerticalScrollBarPolicy(_Qt.ScrollBarPolicy.ScrollBarAsNeeded)


class FooterStatusPanel:
    """Mensagem padrao da barra inferior."""

    @staticmethod
    def default_message() -> str:
        return "Pronto -- execute uma verificacao para comecar."