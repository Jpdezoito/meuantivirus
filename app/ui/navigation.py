"""Componentes de navegacao lateral da interface principal."""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import QButtonGroup, QLabel, QPushButton, QVBoxLayout, QWidget


# Icones unicode por pagina
_NAV_ICONS: dict[str, str] = {
    "dashboard":   "◉",
    "files":       "🔍",
    "processes":   "⚙",
    "startup":     "🚀",
    "browsers":    "🌐",
    "emails":      "✉",
    "audit":       "🛡",
    "quarantine":  "🔒",
    "reports":     "📄",
    "history":     "📋",
    "diagnostics": "💊",
}

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
        self.setMinimumWidth(190)
        self.setMaximumWidth(220)
        self._buttons: dict[str, QPushButton] = {}
        self._button_group = QButtonGroup(self)
        self._button_group.setExclusive(True)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 28, 14, 20)
        layout.setSpacing(2)

        # Logo + nome
        brand_row = QWidget()
        brand_row.setStyleSheet("background: transparent;")
        brand_layout = QVBoxLayout(brand_row)
        brand_layout.setContentsMargins(8, 0, 0, 0)
        brand_layout.setSpacing(2)

        logo = QLabel("🛡 SentinelaPC")
        logo.setObjectName("navBrand")
        subtitle = QLabel("Central de seguranca")
        subtitle.setObjectName("navSubtitle")

        brand_layout.addWidget(logo)
        brand_layout.addWidget(subtitle)
        layout.addWidget(brand_row)
        layout.addSpacing(22)

        # Itens de navegacao
        prev_section = ""
        for page_id, section, label in _NAV_ITEMS:
            if section and section != prev_section:
                section_lbl = QLabel(section)
                section_lbl.setObjectName("navSectionLabel")
                section_lbl.setContentsMargins(10, 10, 0, 4)
                layout.addWidget(section_lbl)
                prev_section = section

            icon = _NAV_ICONS.get(page_id, "•")
            button = QPushButton(f"  {icon}  {label}")
            button.setCheckable(True)
            button.setObjectName("navButton")
            button.setCursor(Qt.CursorShape.PointingHandCursor)
            button.clicked.connect(
                lambda checked=False, target=page_id: self.page_selected.emit(target)
            )
            self._button_group.addButton(button)
            self._buttons[page_id] = button
            layout.addWidget(button)

        layout.addStretch()

        footer = QLabel("v1.0  •  SentinelaPC")
        footer.setObjectName("navFooter")
        footer.setContentsMargins(10, 0, 0, 0)
        layout.addWidget(footer)

    def set_current_page(self, page_id: str) -> None:
        """Marca visualmente a pagina atualmente ativa no empilhamento."""
        button = self._buttons.get(page_id)
        if button is not None:
            button.setChecked(True)
