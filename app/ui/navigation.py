"""Componentes de navegacao lateral da interface principal."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt, QSize, Signal
from PySide6.QtGui import QPixmap
from PySide6.QtWidgets import QButtonGroup, QHBoxLayout, QLabel, QPushButton, QVBoxLayout, QWidget

from app.ui.icons import get_icon, ICON_MAP

_NAV_ITEMS: list[tuple[str, str, str]] = [
    # (page_id, section_label_before | "", text)
    ("dashboard",   "VISAO GERAL",   "Dashboard"),
    ("files",       "SEGURANCA",     "Arquivos"),
    ("processes",   "",              "Processos"),
    ("startup",     "",              "Inicializacao"),
    ("browsers",    "",              "Navegadores"),
    ("emails",      "",              "E-mails"),
    ("audit",       "",              "Auditoria"),
    ("quarantine",  "FERRAMENTAS",   "Quarentena"),
    ("reports",     "",              "Relatorios"),
    ("history",     "",              "Historico"),
    ("diagnostics", "",              "Diagnostico"),
]


class SidebarNavigation(QWidget):
    """Barra lateral responsavel por alternar entre as paginas principais."""

    page_selected = Signal(str)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("navSidebar")
        self.setMinimumWidth(236)
        self.setMaximumWidth(260)
        self._buttons: dict[str, QPushButton] = {}
        self._button_group = QButtonGroup(self)
        self._button_group.setExclusive(True)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 22, 18, 18)
        layout.setSpacing(6)

        brand_row = QWidget()
        brand_row.setStyleSheet("background: transparent;")
        brand_layout = QHBoxLayout(brand_row)
        brand_layout.setContentsMargins(0, 0, 0, 0)
        brand_layout.setSpacing(0)

        logo_image = QLabel()
        logo_image.setObjectName("navLogoImage")
        logo_image.setFixedSize(232, 168)
        logo_image.setAlignment(Qt.AlignmentFlag.AlignCenter)

        base_dir = Path(__file__).resolve().parents[2]
        logo_candidates = [
            base_dir / "app" / "assets" / "branding" / "sentinelapc.png",
            base_dir / "app" / "assets" / "branding" / "logo-app-256.png",
            base_dir / "sentinelapc.png",
        ]
        for logo_path in logo_candidates:
            if not logo_path.exists():
                continue

            pixmap = QPixmap(str(logo_path))
            if pixmap.isNull():
                continue

            scaled = pixmap.scaled(
                224,
                160,
                Qt.AspectRatioMode.KeepAspectRatio,
                Qt.TransformationMode.SmoothTransformation,
            )
            logo_image.setPixmap(scaled)
            break
        if logo_image.pixmap() is None:
            logo_image.setText("SP")
            logo_image.setObjectName("navMonogram")

        brand_layout.addStretch(1)
        brand_layout.addWidget(logo_image, 0, Qt.AlignmentFlag.AlignCenter)
        brand_layout.addStretch(1)
        layout.addWidget(brand_row)
        layout.addSpacing(10)

        prev_section = ""
        for page_id, section, label in _NAV_ITEMS:
            if section and section != prev_section:
                section_lbl = QLabel(section)
                section_lbl.setObjectName("navSectionLabel")
                section_lbl.setContentsMargins(10, 12, 0, 6)
                layout.addWidget(section_lbl)
                prev_section = section

            button = QPushButton(label)
            button.setCheckable(True)
            button.setObjectName("navButton")
            button.setCursor(Qt.CursorShape.PointingHandCursor)

            icon_name = ICON_MAP.get(page_id, "dashboard")
            btn_icon = get_icon(icon_name, size=32, color="#f7fbff")
            if btn_icon:
                button.setIcon(btn_icon)
                button.setIconSize(QSize(32, 32))

            button.clicked.connect(
                lambda checked=False, target=page_id: self.page_selected.emit(target)
            )
            self._button_group.addButton(button)
            self._buttons[page_id] = button
            layout.addWidget(button)

        layout.addStretch()

        footer_card = QWidget()
        footer_card.setObjectName("navFooterCard")
        footer_layout = QVBoxLayout(footer_card)
        footer_layout.setContentsMargins(14, 14, 14, 14)
        footer_layout.setSpacing(4)

        footer_title = QLabel("Pronto para verificacao")
        footer_title.setObjectName("navFooterTitle")
        footer_body = QLabel("Acesse qualquer modulo ao lado para iniciar scans, auditorias ou revisar itens em quarentena.")
        footer_body.setObjectName("navFooter")
        footer_body.setWordWrap(True)

        footer_layout.addWidget(footer_title)
        footer_layout.addWidget(footer_body)
        layout.addWidget(footer_card)

    def set_current_page(self, page_id: str) -> None:
        """Marca visualmente a pagina atualmente ativa no empilhamento."""
        button = self._buttons.get(page_id)
        if button is not None:
            button.setChecked(True)
