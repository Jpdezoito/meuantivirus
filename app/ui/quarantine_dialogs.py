"""Dialogos simples para operacoes manuais de quarentena na interface."""

from __future__ import annotations

from collections.abc import Sequence

from PySide6.QtWidgets import (
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from app.services.file_scan_models import FileScanResult
from app.services.process_scan_models import ProcessScanResult
from app.services.quarantine_models import QuarantineItem
from app.services.startup_scan_models import StartupScanResult


class QuarantineSelectionDialog(QDialog):
    """Permite ao usuario selecionar um arquivo suspeito para isolar."""

    def __init__(self, suspicious_files: Sequence[FileScanResult], parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._suspicious_files = list(suspicious_files)
        self._selected_results: list[FileScanResult] = []
        self.setWindowTitle("Mover arquivo para quarentena")
        self.resize(860, 420)

        layout = QVBoxLayout(self)
        layout.setSpacing(14)

        guidance = QLabel("Selecione um ou mais arquivos suspeitos da ultima verificacao para enviar para quarentena.")
        guidance.setWordWrap(True)
        layout.addWidget(guidance)

        self.select_all_checkbox = QCheckBox("Selecionar todos")
        self.select_all_checkbox.toggled.connect(self._toggle_select_all)
        layout.addWidget(self.select_all_checkbox)

        self.table = QTableWidget(len(self._suspicious_files), 4)
        self.table.setHorizontalHeaderLabels(["Arquivo", "Risco", "Score", "Motivo"])
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableWidget.SelectionMode.MultiSelection)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setAlternatingRowColors(True)

        for row_index, result in enumerate(self._suspicious_files):
            self.table.setItem(row_index, 0, QTableWidgetItem(str(result.path)))
            self.table.setItem(row_index, 1, QTableWidgetItem(result.initial_risk_level.value))
            self.table.setItem(row_index, 2, QTableWidgetItem(str(result.heuristic_score)))
            self.table.setItem(row_index, 3, QTableWidgetItem(result.alert_reason))

        if self._suspicious_files:
            self.table.selectRow(0)

        layout.addWidget(self.table)

        form_layout = QFormLayout()
        self.reason_input = QLineEdit()
        self.reason_input.setPlaceholderText("Opcional. Ex.: arquivo executavel em pasta temporaria")
        form_layout.addRow("Motivo da quarentena (opcional):", self.reason_input)
        layout.addLayout(form_layout)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.button(QDialogButtonBox.StandardButton.Ok).setText("Mover para quarentena")
        buttons.button(QDialogButtonBox.StandardButton.Cancel).setText("Cancelar")
        buttons.accepted.connect(self._confirm_selection)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    @property
    def selected_results(self) -> list[FileScanResult]:
        """Retorna os itens escolhidos apos a confirmacao do usuario."""
        return list(self._selected_results)

    @property
    def reason(self) -> str:
        """Retorna o motivo informado pelo usuario."""
        return self.reason_input.text().strip()

    def _confirm_selection(self) -> None:
        """Valida a selecao antes de encerrar o dialogo com sucesso."""
        selected_rows = sorted({index.row() for index in self.table.selectionModel().selectedRows()})
        if not selected_rows:
            QMessageBox.warning(self, "Selecao obrigatoria", "Selecione um arquivo suspeito para continuar.")
            return

        self._selected_results = [self._suspicious_files[row] for row in selected_rows if 0 <= row < len(self._suspicious_files)]
        self.accept()

    def _toggle_select_all(self, checked: bool) -> None:
        """Seleciona ou limpa todas as linhas da tabela."""
        if checked:
            self.table.selectAll()
            return

        self.table.clearSelection()


class QuarantineListDialog(QDialog):
    """Exibe uma lista simples de itens isolados e permite restauracao manual."""

    def __init__(self, items: Sequence[QuarantineItem], parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._items = list(items)
        self._selected_item_id: int | None = None
        self.setWindowTitle("Quarentena")
        self.resize(980, 460)

        layout = QVBoxLayout(self)
        layout.setSpacing(14)

        summary = QLabel(
            "Lista de arquivos isolados. Itens restaurados permanecem no historico para auditoria futura."
        )
        summary.setWordWrap(True)
        layout.addWidget(summary)

        self.table = QTableWidget(len(self._items), 6)
        self.table.setHorizontalHeaderLabels(["ID", "Nome original", "Risco", "Status", "Data", "Origem"])
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setAlternatingRowColors(True)

        for row_index, item in enumerate(self._items):
            self.table.setItem(row_index, 0, QTableWidgetItem(str(item.id)))
            self.table.setItem(row_index, 1, QTableWidgetItem(item.original_name))
            self.table.setItem(row_index, 2, QTableWidgetItem(item.risk_level.value))
            self.table.setItem(row_index, 3, QTableWidgetItem(item.status))
            self.table.setItem(row_index, 4, QTableWidgetItem(item.created_at))
            self.table.setItem(row_index, 5, QTableWidgetItem(str(item.original_path)))

        if self._items:
            self.table.selectRow(0)

        layout.addWidget(self.table)

        actions_layout = QHBoxLayout()
        self.restore_button = QPushButton("Restaurar selecionado")
        self.restore_button.clicked.connect(self._request_restore)
        close_button = QPushButton("Fechar")
        close_button.clicked.connect(self.reject)
        actions_layout.addWidget(self.restore_button)
        actions_layout.addStretch()
        actions_layout.addWidget(close_button)
        layout.addLayout(actions_layout)

    @property
    def selected_item_id(self) -> int | None:
        """Retorna o identificador pedido para restauracao."""
        return self._selected_item_id

    def _request_restore(self) -> None:
        """Valida o item selecionado e impede restauracao duplicada."""
        selected_row = self.table.currentRow()
        if selected_row < 0 or selected_row >= len(self._items):
            QMessageBox.warning(self, "Selecao obrigatoria", "Selecione um item em quarentena para restaurar.")
            return

        selected_item = self._items[selected_row]
        if not selected_item.is_active:
            QMessageBox.information(self, "Item ja restaurado", "O item selecionado ja foi restaurado e esta apenas no historico.")
            return

        self._selected_item_id = selected_item.id
        self.accept()


class ProcessQuarantineSelectionDialog(QDialog):
    """Permite selecionar processos suspeitos para mover seus executaveis para quarentena."""

    def __init__(self, suspicious_processes: Sequence[ProcessScanResult], parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._suspicious_processes = [item for item in suspicious_processes if item.executable_path is not None]
        self._selected_results: list[ProcessScanResult] = []
        self.setWindowTitle("Mover processo para quarentena")
        self.resize(920, 440)

        layout = QVBoxLayout(self)
        layout.setSpacing(14)

        guidance = QLabel("Selecione um ou mais processos suspeitos para enviar os executaveis para quarentena.")
        guidance.setWordWrap(True)
        layout.addWidget(guidance)

        self.select_all_checkbox = QCheckBox("Selecionar todos")
        self.select_all_checkbox.toggled.connect(self._toggle_select_all)
        layout.addWidget(self.select_all_checkbox)

        self.table = QTableWidget(len(self._suspicious_processes), 5)
        self.table.setHorizontalHeaderLabels(["Processo", "PID", "Risco", "Score", "Executavel"])
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableWidget.SelectionMode.MultiSelection)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setAlternatingRowColors(True)

        for row_index, result in enumerate(self._suspicious_processes):
            self.table.setItem(row_index, 0, QTableWidgetItem(result.name))
            self.table.setItem(row_index, 1, QTableWidgetItem(str(result.pid)))
            self.table.setItem(row_index, 2, QTableWidgetItem(result.initial_risk_level.value))
            self.table.setItem(row_index, 3, QTableWidgetItem(str(result.heuristic_score)))
            self.table.setItem(row_index, 4, QTableWidgetItem(str(result.executable_path or "")))

        if self._suspicious_processes:
            self.table.selectRow(0)

        layout.addWidget(self.table)

        form_layout = QFormLayout()
        self.reason_input = QLineEdit()
        self.reason_input.setPlaceholderText("Opcional. Ex.: processo em local temporario")
        form_layout.addRow("Motivo da quarentena (opcional):", self.reason_input)
        layout.addLayout(form_layout)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.button(QDialogButtonBox.StandardButton.Ok).setText("Mover para quarentena")
        buttons.button(QDialogButtonBox.StandardButton.Cancel).setText("Cancelar")
        buttons.accepted.connect(self._confirm_selection)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    @property
    def selected_results(self) -> list[ProcessScanResult]:
        return list(self._selected_results)

    @property
    def reason(self) -> str:
        return self.reason_input.text().strip()

    def _confirm_selection(self) -> None:
        selected_rows = sorted({index.row() for index in self.table.selectionModel().selectedRows()})
        if not selected_rows:
            QMessageBox.warning(self, "Selecao obrigatoria", "Selecione um processo suspeito para continuar.")
            return

        self._selected_results = [
            self._suspicious_processes[row]
            for row in selected_rows
            if 0 <= row < len(self._suspicious_processes)
        ]
        self.accept()

    def _toggle_select_all(self, checked: bool) -> None:
        if checked:
            self.table.selectAll()
            return

        self.table.clearSelection()


class StartupQuarantineSelectionDialog(QDialog):
    """Permite selecionar itens de startup para mover executaveis para quarentena."""

    def __init__(self, suspicious_items: Sequence[StartupScanResult], parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._suspicious_items = [item for item in suspicious_items if item.executable_path is not None]
        self._selected_results: list[StartupScanResult] = []
        self.setWindowTitle("Mover item de inicializacao para quarentena")
        self.resize(980, 450)

        layout = QVBoxLayout(self)
        layout.setSpacing(14)

        guidance = QLabel("Selecione um ou mais itens suspeitos de inicializacao para enviar para quarentena.")
        guidance.setWordWrap(True)
        layout.addWidget(guidance)

        self.select_all_checkbox = QCheckBox("Selecionar todos")
        self.select_all_checkbox.toggled.connect(self._toggle_select_all)
        layout.addWidget(self.select_all_checkbox)

        self.table = QTableWidget(len(self._suspicious_items), 5)
        self.table.setHorizontalHeaderLabels(["Nome", "Origem", "Risco", "Score", "Executavel"])
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableWidget.SelectionMode.MultiSelection)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setAlternatingRowColors(True)

        for row_index, result in enumerate(self._suspicious_items):
            self.table.setItem(row_index, 0, QTableWidgetItem(result.name))
            self.table.setItem(row_index, 1, QTableWidgetItem(result.origin))
            self.table.setItem(row_index, 2, QTableWidgetItem(result.risk_level.value))
            self.table.setItem(row_index, 3, QTableWidgetItem(str(result.heuristic_score)))
            self.table.setItem(row_index, 4, QTableWidgetItem(str(result.executable_path or "")))

        if self._suspicious_items:
            self.table.selectRow(0)

        layout.addWidget(self.table)

        form_layout = QFormLayout()
        self.reason_input = QLineEdit()
        self.reason_input.setPlaceholderText("Opcional. Ex.: item de startup suspeito")
        form_layout.addRow("Motivo da quarentena (opcional):", self.reason_input)
        layout.addLayout(form_layout)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.button(QDialogButtonBox.StandardButton.Ok).setText("Mover para quarentena")
        buttons.button(QDialogButtonBox.StandardButton.Cancel).setText("Cancelar")
        buttons.accepted.connect(self._confirm_selection)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    @property
    def selected_results(self) -> list[StartupScanResult]:
        return list(self._selected_results)

    @property
    def reason(self) -> str:
        return self.reason_input.text().strip()

    def _confirm_selection(self) -> None:
        selected_rows = sorted({index.row() for index in self.table.selectionModel().selectedRows()})
        if not selected_rows:
            QMessageBox.warning(self, "Selecao obrigatoria", "Selecione um item de inicializacao para continuar.")
            return

        self._selected_results = [
            self._suspicious_items[row]
            for row in selected_rows
            if 0 <= row < len(self._suspicious_items)
        ]
        self.accept()

    def _toggle_select_all(self, checked: bool) -> None:
        if checked:
            self.table.selectAll()
            return

        self.table.clearSelection()