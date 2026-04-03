"""Dialogo dedicado para inspecao dos itens suspeitos encontrados na analise de navegadores."""

from __future__ import annotations

import hashlib
import subprocess
import webbrowser
from pathlib import Path

from PySide6.QtWidgets import (
    QDialog,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from app.services.browser_scan_models import BrowserScanItem


_VIRUSTOTAL_URL = "https://www.virustotal.com/gui/file/{sha256}"
_VIRUSTOTAL_SEARCH_URL = "https://www.virustotal.com/gui/search/{name}"


class BrowserSuspiciousItemsDialog(QDialog):
    """Exibe os itens suspeitos da ultima analise com acoes rapidas por linha."""

    COLUMNS = [
        "Nome",
        "Navegador",
        "Tipo",
        "Risco",
        "Score",
        "Motivos",
        "Caminho",
        "Hash SHA-256",
    ]
    _ACTION_COL_WIDTH = 112

    def __init__(self, items: list[BrowserScanItem], parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._items = items
        self._hashes: dict[int, str] = {}

        self.setWindowTitle("Itens suspeitos — Navegadores")
        self.resize(1200, 520)
        self.setMinimumWidth(900)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 18, 18, 18)
        layout.setSpacing(14)

        title = QLabel(f"Itens suspeitos encontrados: {len(items)}")
        title.setObjectName("pageTitleLarge")
        layout.addWidget(title)

        hint = QLabel(
            "Selecione uma linha e use os botoes para abrir a localizacao no Explorer, "
            "calcular o hash SHA-256 ou consultar no VirusTotal."
        )
        hint.setObjectName("pageSubtitle")
        hint.setWordWrap(True)
        layout.addWidget(hint)

        self.table = QTableWidget(len(items), len(self.COLUMNS))
        self.table.setObjectName("dataTable")
        self.table.setHorizontalHeaderLabels(self.COLUMNS)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setDefaultSectionSize(180)
        self.table.setAlternatingRowColors(True)
        self.table.setWordWrap(False)
        self.table.horizontalHeader().setStretchLastSection(True)

        for row, item in enumerate(items):
            path_text = str(item.path) if item.path is not None else ""
            reasons_text = "; ".join(item.reasons) if item.reasons else "-"
            values = [
                item.name,
                item.browser,
                item.item_type,
                item.risk_level.value,
                str(item.score),
                reasons_text,
                path_text,
                "",
            ]
            for col, value in enumerate(values):
                self.table.setItem(row, col, QTableWidgetItem(value))

        layout.addWidget(self.table, 1)

        action_bar = QHBoxLayout()
        action_bar.setSpacing(10)

        self.btn_open_folder = QPushButton("Abrir localizacao")
        self.btn_open_folder.setObjectName("primaryActionButton")
        self.btn_open_folder.setFixedHeight(40)
        self.btn_open_folder.clicked.connect(self._open_folder)
        action_bar.addWidget(self.btn_open_folder)

        self.btn_hash = QPushButton("Calcular hash SHA-256")
        self.btn_hash.setObjectName("primaryActionButton")
        self.btn_hash.setFixedHeight(40)
        self.btn_hash.clicked.connect(self._compute_hash)
        action_bar.addWidget(self.btn_hash)

        self.btn_vt = QPushButton("Verificar no VirusTotal")
        self.btn_vt.setObjectName("primaryActionButton")
        self.btn_vt.setFixedHeight(40)
        self.btn_vt.clicked.connect(self._open_virustotal)
        action_bar.addWidget(self.btn_vt)

        action_bar.addStretch()

        close_btn = QPushButton("Fechar")
        close_btn.setObjectName("secondaryActionButton")
        close_btn.setFixedHeight(40)
        close_btn.clicked.connect(self.accept)
        action_bar.addWidget(close_btn)

        layout.addLayout(action_bar)

        if items:
            self.table.selectRow(0)

    def _selected_row(self) -> int:
        rows = self.table.selectionModel().selectedRows()
        return rows[0].row() if rows else -1

    def _selected_item(self) -> BrowserScanItem | None:
        row = self._selected_row()
        if row < 0 or row >= len(self._items):
            return None
        return self._items[row]

    def _selected_path(self) -> Path | None:
        item = self._selected_item()
        if item is None:
            QMessageBox.warning(self, "Selecione um item", "Clique em uma linha antes de usar esta acao.")
            return None
        if item.path is None:
            QMessageBox.information(self, "Caminho indisponivel", f"O item '{item.name}' nao possui caminho de arquivo registrado.")
            return None
        p = Path(item.path)
        if not p.exists():
            answer = QMessageBox.question(
                self,
                "Arquivo nao encontrado",
                f"O arquivo '{p}' nao foi encontrado no disco.\nDeseja continuar mesmo assim?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            if answer != QMessageBox.StandardButton.Yes:
                return None
        return p

    def _open_folder(self) -> None:
        """Abre a pasta do arquivo no Windows Explorer com o item selecionado."""
        p = self._selected_path()
        if p is None:
            return
        target = p if p.is_dir() else p.parent
        try:
            if p.exists() and not p.is_dir():
                subprocess.Popen(["explorer", "/select,", str(p)])
            else:
                subprocess.Popen(["explorer", str(target)])
        except OSError as error:
            QMessageBox.critical(self, "Falha ao abrir pasta", str(error))

    def _compute_hash(self) -> None:
        """Calcula o SHA-256 do arquivo selecionado e exibe na tabela e em dialogo."""
        row = self._selected_row()
        if row < 0:
            QMessageBox.warning(self, "Selecione um item", "Clique em uma linha antes de calcular o hash.")
            return
        item = self._items[row]
        if item.path is None:
            QMessageBox.information(self, "Caminho indisponivel", f"'{item.name}' nao possui caminho de arquivo.")
            return
        p = Path(item.path)
        if not p.exists() or p.is_dir():
            QMessageBox.warning(self, "Arquivo nao encontrado", f"Nao foi possivel localizar '{p}' no disco.")
            return

        if row in self._hashes:
            digest = self._hashes[row]
        else:
            try:
                hasher = hashlib.sha256()
                with p.open("rb") as fh:
                    for chunk in iter(lambda: fh.read(65536), b""):
                        hasher.update(chunk)
                digest = hasher.hexdigest()
            except OSError as error:
                QMessageBox.critical(self, "Erro ao calcular hash", str(error))
                return
            self._hashes[row] = digest

        hash_cell = self.table.item(row, self.COLUMNS.index("Hash SHA-256"))
        if hash_cell is not None:
            hash_cell.setText(digest)

        QMessageBox.information(
            self,
            "Hash SHA-256",
            f"Arquivo: {p.name}\n\nSHA-256:\n{digest}\n\nCopie o hash acima e cole no VirusTotal para verificar.",
        )

    def _open_virustotal(self) -> None:
        """Abre o VirusTotal no navegador com o hash (se calculado) ou busca por nome."""
        row = self._selected_row()
        if row < 0:
            QMessageBox.warning(self, "Selecione um item", "Clique em uma linha antes de consultar no VirusTotal.")
            return
        item = self._items[row]

        if row in self._hashes:
            url = _VIRUSTOTAL_URL.format(sha256=self._hashes[row])
        else:
            safe_name = item.name.replace(" ", "+")
            url = _VIRUSTOTAL_SEARCH_URL.format(name=safe_name)
            QMessageBox.information(
                self,
                "Hash nao calculado",
                "O hash SHA-256 deste arquivo ainda nao foi calculado.\n\n"
                "O navegador vai abrir uma busca por nome no VirusTotal.\n"
                "Para uma consulta exata, clique em 'Calcular hash SHA-256' primeiro.",
            )

        try:
            webbrowser.open(url)
        except Exception as error:
            QMessageBox.critical(self, "Falha ao abrir navegador", str(error))
