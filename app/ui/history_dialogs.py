"""Dialogo simples para visualizacao do historico de verificacoes."""

from __future__ import annotations

from collections.abc import Sequence

from PySide6.QtWidgets import QDialog, QLabel, QPushButton, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget

from app.data.history_models import HistoryEntry


class HistoryDialog(QDialog):
    """Exibe as entradas persistidas do historico em uma tabela simples."""

    def __init__(self, entries: Sequence[HistoryEntry], parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._entries = list(entries)
        self.setWindowTitle("Historico de verificacoes")
        self.resize(980, 480)

        layout = QVBoxLayout(self)
        layout.setSpacing(14)

        description = QLabel(
            "Lista das verificacoes registradas localmente, com resumo, volume analisado e caminho do relatorio quando existir."
        )
        description.setWordWrap(True)
        layout.addWidget(description)

        self.table = QTableWidget(len(self._entries), 6)
        self.table.setHorizontalHeaderLabels(["Data/Hora", "Tipo", "Analisados", "Suspeitos", "Resumo", "Relatorio"])
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setAlternatingRowColors(True)

        for row_index, entry in enumerate(self._entries):
            self.table.setItem(row_index, 0, QTableWidgetItem(entry.created_at))
            self.table.setItem(row_index, 1, QTableWidgetItem(entry.scan_type))
            self.table.setItem(row_index, 2, QTableWidgetItem(str(entry.analyzed_count)))
            self.table.setItem(row_index, 3, QTableWidgetItem(str(entry.suspicious_count)))
            self.table.setItem(row_index, 4, QTableWidgetItem(entry.summary))
            self.table.setItem(row_index, 5, QTableWidgetItem(entry.report_path or "-"))

        layout.addWidget(self.table)

        close_button = QPushButton("Fechar")
        close_button.clicked.connect(self.accept)
        layout.addWidget(close_button)