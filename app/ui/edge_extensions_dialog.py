"""Dialogo de gerenciamento e auditoria de extensoes do Microsoft Edge."""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QDialog,
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from app.services.edge_extension_models import EdgeExtensionInventory, EdgeExtensionRecord


class EdgeExtensionsDialog(QDialog):
    """Apresenta extensoes do Edge e expõe acoes seguras de remediacao."""

    action_requested = Signal(str, object)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Gerenciar extensoes do Microsoft Edge")
        self.resize(1180, 760)
        self.setModal(True)

        self._extensions: list[EdgeExtensionRecord] = []
        self._inventory = EdgeExtensionInventory()

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(14)

        title = QLabel("Extensoes do Microsoft Edge")
        title.setObjectName("dialogTitle")
        layout.addWidget(title)

        self.summary_label = QLabel("Carregando inventario...")
        self.summary_label.setWordWrap(True)
        layout.addWidget(self.summary_label)

        self.table = QTableWidget(0, 7)
        self.table.setHorizontalHeaderLabels(
            ["Nome", "ID", "Versao", "Perfil", "Status", "Risco", "Caminho"]
        )
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.itemSelectionChanged.connect(self._update_details_panel)
        layout.addWidget(self.table, 1)

        details_title = QLabel("Detalhes e criterios de auditoria")
        details_title.setObjectName("sectionTitle")
        layout.addWidget(details_title)

        self.details_box = QPlainTextEdit()
        self.details_box.setReadOnly(True)
        self.details_box.setMinimumHeight(180)
        layout.addWidget(self.details_box)

        button_row = QHBoxLayout()
        button_row.setSpacing(10)

        self.refresh_button = QPushButton("Atualizar")
        self.disable_button = QPushButton("Desativar")
        self.quarantine_button = QPushButton("Mover para quarentena")
        self.remove_button = QPushButton("Remover")
        self.close_button = QPushButton("Fechar")

        self.refresh_button.clicked.connect(lambda: self.action_requested.emit("refresh", None))
        self.disable_button.clicked.connect(lambda: self._emit_action("disable"))
        self.quarantine_button.clicked.connect(lambda: self._emit_action("quarantine"))
        self.remove_button.clicked.connect(lambda: self._emit_action("remove"))
        self.close_button.clicked.connect(self.reject)

        for button in (
            self.refresh_button,
            self.disable_button,
            self.quarantine_button,
            self.remove_button,
            self.close_button,
        ):
            button_row.addWidget(button)

        layout.addLayout(button_row)
        self._refresh_buttons()

    def set_inventory(self, inventory: EdgeExtensionInventory) -> None:
        self._inventory = inventory
        self._extensions = list(inventory.extensions)
        self.table.setRowCount(len(self._extensions))

        for row, extension in enumerate(self._extensions):
            values = [
                extension.name,
                extension.extension_id,
                extension.version,
                extension.profile_name,
                extension.status,
                "Suspeita" if extension.suspicious_reasons else "Normal",
                str(extension.install_path),
            ]
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setData(Qt.ItemDataRole.UserRole, extension)
                if extension.suspicious_reasons:
                    item.setForeground(QColor("#ffcf78"))
                self.table.setItem(row, column, item)

        suspicious_count = sum(1 for extension in self._extensions if extension.suspicious_reasons)
        error_count = len(inventory.errors)
        self.summary_label.setText(
            (
                f"Perfis encontrados: {len(inventory.profiles)} | "
                f"Extensoes listadas: {len(self._extensions)} | "
                f"Extensoes suspeitas: {suspicious_count} | "
                f"Erros de leitura: {error_count}"
            )
        )

        if self._extensions:
            self.table.selectRow(0)
        else:
            self.details_box.setPlainText(self._build_error_text())

        self._refresh_buttons()

    def current_extension(self) -> EdgeExtensionRecord | None:
        current_row = self.table.currentRow()
        if current_row < 0 or current_row >= len(self._extensions):
            return None
        return self._extensions[current_row]

    def _emit_action(self, action_name: str) -> None:
        extension = self.current_extension()
        if extension is None:
            return
        self.action_requested.emit(action_name, extension)

    def _update_details_panel(self) -> None:
        extension = self.current_extension()
        if extension is None:
            self.details_box.setPlainText(self._build_error_text())
            self._refresh_buttons()
            return

        permissions = ", ".join(extension.permissions) if extension.permissions else "Nenhuma"
        host_permissions = ", ".join(extension.host_permissions) if extension.host_permissions else "Nenhuma"
        reasons = extension.suspicious_reasons or ["Nenhum criterio de suspeita acionado."]

        lines = [
            f"Nome: {extension.name}",
            f"ID: {extension.extension_id}",
            f"Versao: {extension.version}",
            f"Perfil: {extension.profile_name}",
            f"Status: {extension.status}",
            f"Caminho: {extension.install_path}",
            f"Manifest: {extension.manifest_path or 'Nao encontrado'}",
            f"Permissoes: {permissions}",
            f"Hosts: {host_permissions}",
            "",
            "Criterios de auditoria:",
            *[f"- {reason}" for reason in reasons],
        ]

        if self._inventory.errors:
            lines.extend(["", "Erros de leitura do inventario:"])
            lines.extend([f"- {error.source}: {error.message}" for error in self._inventory.errors[:10]])

        self.details_box.setPlainText("\n".join(lines))
        self._refresh_buttons()

    def _refresh_buttons(self) -> None:
        has_selection = self.current_extension() is not None
        self.disable_button.setEnabled(has_selection)
        self.quarantine_button.setEnabled(has_selection)
        self.remove_button.setEnabled(has_selection)

    def _build_error_text(self) -> str:
        if not self._inventory.errors:
            return "Nenhuma extensao foi encontrada nos perfis atuais do Edge."
        lines = ["Nao foi possivel listar extensoes do Edge:"]
        lines.extend([f"- {error.source}: {error.message}" for error in self._inventory.errors])
        return "\n".join(lines)
