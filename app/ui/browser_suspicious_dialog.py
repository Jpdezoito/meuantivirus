"""Dialogo dedicado para inspecao dos itens suspeitos encontrados na analise de navegadores."""

from __future__ import annotations

import hashlib
import logging
import os
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
_LOGGER = logging.getLogger("sentinelapc")


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
        # Cache por linha: (arquivo_real_usado_no_hash, digest)
        self._hashes: dict[int, tuple[str, str]] = {}

        self.setWindowTitle("Itens suspeitos - Navegadores")
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
            QMessageBox.information(
                self,
                "Caminho indisponivel",
                f"O item '{item.name}' nao possui caminho de arquivo registrado.",
            )
            return None
        return Path(item.path)

    def _open_folder(self) -> None:
        """Abre a pasta do arquivo no Windows Explorer com o item selecionado."""
        p = self._selected_path()
        if p is None:
            return
        target = p if p.is_dir() else p.parent
        try:
            if p.exists() and p.is_file():
                subprocess.Popen(["explorer", "/select,", str(p)])
            else:
                subprocess.Popen(["explorer", str(target)])
        except OSError as error:
            QMessageBox.critical(self, "Falha ao abrir pasta", str(error))

    def _compute_hash(self) -> None:
        """Calcula o SHA-256 do arquivo selecionado com validacao robusta de caminho."""
        row = self._selected_row()
        if row < 0:
            QMessageBox.warning(self, "Selecione um item", "Clique em uma linha antes de calcular o hash.")
            return

        item = self._items[row]
        if item.path is None:
            _LOGGER.warning("[HashDialog] Item sem caminho | nome=%s | tipo=%s", item.name, item.item_type)
            QMessageBox.information(
                self,
                "Caminho indisponivel",
                (
                    f"O item '{item.name}' foi listado na varredura, mas nao possui caminho de disco associado.\n\n"
                    "Isso pode ocorrer com registros historicos ou itens agregados do navegador."
                ),
            )
            return

        original_path = Path(item.path)
        resolved_target, resolution_note, resolution_code = self._resolve_hash_target(item, original_path)

        _LOGGER.info(
            "[HashDialog] Solicitação de hash | nome=%s | tipo_item=%s | caminho_recebido=%s | existe=%s | is_file=%s | is_dir=%s | resultado=%s",
            item.name,
            item.item_type,
            original_path,
            original_path.exists(),
            original_path.is_file() if original_path.exists() else False,
            original_path.is_dir() if original_path.exists() else False,
            resolution_code,
        )

        if resolved_target is None:
            if resolution_code == "missing":
                QMessageBox.information(
                    self,
                    "Item nao disponivel",
                    (
                        "O item foi listado na varredura, mas nao esta mais disponivel no caminho original.\n\n"
                        f"Caminho registrado: {original_path}\n"
                        "Ele pode ter sido removido, movido ou atualizado apos a analise."
                    ),
                )
                return
            if resolution_code == "directory_no_hash_target":
                QMessageBox.information(
                    self,
                    "Item em pasta",
                    (
                        f"O caminho selecionado e uma pasta: {original_path}\n\n"
                        "Nao ha um arquivo principal valido para calcular SHA-256 neste momento."
                    ),
                )
                return

            QMessageBox.warning(
                self,
                "Nao foi possivel calcular hash",
                resolution_note or "Nao foi possivel resolver um arquivo valido para hash.",
            )
            return

        cache_entry = self._hashes.get(row)
        if cache_entry is not None and cache_entry[0] == str(resolved_target):
            digest = cache_entry[1]
        else:
            try:
                hasher = hashlib.sha256()
                with resolved_target.open("rb") as fh:
                    for chunk in iter(lambda: fh.read(65536), b""):
                        hasher.update(chunk)
                digest = hasher.hexdigest()
                _LOGGER.info(
                    "[HashDialog] Hash calculado com sucesso | nome=%s | arquivo=%s | sha256=%s...",
                    item.name,
                    resolved_target,
                    digest[:16],
                )
            except OSError as error:
                _LOGGER.warning(
                    "[HashDialog] Falha ao calcular hash | nome=%s | arquivo=%s | erro=%s",
                    item.name,
                    resolved_target,
                    error,
                )
                QMessageBox.critical(
                    self,
                    "Erro ao calcular hash",
                    (
                        "O item foi encontrado, mas ficou inacessivel durante a leitura.\n"
                        "Tente novamente ou execute uma nova analise.\n\n"
                        f"Detalhe tecnico: {error}"
                    ),
                )
                return
            self._hashes[row] = (str(resolved_target), digest)

        hash_cell = self.table.item(row, self.COLUMNS.index("Hash SHA-256"))
        if hash_cell is not None:
            hash_cell.setText(digest)

        detail = f"\nArquivo resolvido: {resolved_target}\n" if resolution_note else "\n"
        QMessageBox.information(
            self,
            "Hash SHA-256",
            (
                f"Arquivo: {resolved_target.name}{detail}\n"
                f"SHA-256:\n{digest}\n\n"
                "Copie o hash acima e cole no VirusTotal para verificar."
            ),
        )

    def _resolve_hash_target(
        self,
        item: BrowserScanItem,
        original_path: Path,
    ) -> tuple[Path | None, str, str]:
        """Resolve o melhor arquivo para hash sem assumir que o caminho original ainda e valido."""
        if original_path.exists() and original_path.is_file():
            return original_path, "", "ok_file"

        if original_path.exists() and original_path.is_dir():
            manifest = self._resolve_manifest_from_directory(original_path)
            if manifest is not None:
                return manifest, "Item de extensao: hash calculado no manifest.json ativo.", "ok_directory_manifest"
            return None, "O caminho aponta para pasta sem arquivo principal para hash.", "directory_no_hash_target"

        if self._is_extension_item(item):
            moved_manifest = self._try_locate_moved_extension_manifest(item, original_path)
            if moved_manifest is not None:
                return (
                    moved_manifest,
                    "Caminho original nao existe mais; hash calculado na versao atual da extensao.",
                    "ok_moved_extension",
                )

        return None, "Caminho registrado nao existe no disco no momento.", "missing"

    def _is_extension_item(self, item: BrowserScanItem) -> bool:
        item_type = (item.item_type or "").lower()
        return "extens" in item_type or item.extension_id is not None

    def _resolve_manifest_from_directory(self, directory: Path) -> Path | None:
        direct_manifest = directory / "manifest.json"
        if direct_manifest.exists() and direct_manifest.is_file():
            return direct_manifest

        candidates: list[Path] = []
        try:
            for child in directory.iterdir():
                if not child.is_dir():
                    continue
                candidate = child / "manifest.json"
                if candidate.exists() and candidate.is_file():
                    candidates.append(candidate)
        except OSError:
            return None

        if not candidates:
            return None

        return max(candidates, key=lambda p: p.stat().st_mtime)

    def _try_locate_moved_extension_manifest(self, item: BrowserScanItem, original_path: Path) -> Path | None:
        extension_id = (item.extension_id or "").strip()
        candidate_roots = self._build_extension_candidate_roots(item.browser, extension_id, original_path)

        manifests: list[Path] = []
        for root in candidate_roots:
            if not root.exists() or not root.is_dir():
                continue
            manifest = self._resolve_manifest_from_directory(root)
            if manifest is not None:
                manifests.append(manifest)

        if not manifests:
            return None

        return max(manifests, key=lambda p: p.stat().st_mtime)

    def _build_extension_candidate_roots(self, browser: str, extension_id: str, original_path: Path) -> list[Path]:
        roots: list[Path] = []
        local_appdata = Path(os.environ.get("LOCALAPPDATA", str(Path.home() / "AppData" / "Local")))
        roaming_appdata = Path(os.environ.get("APPDATA", str(Path.home() / "AppData" / "Roaming")))

        normalized_browser = (browser or "").lower()
        if extension_id:
            if "chrome" in normalized_browser:
                user_data = local_appdata / "Google" / "Chrome" / "User Data"
                roots.extend(user_data.glob(f"*/Extensions/{extension_id}"))
            elif "edge" in normalized_browser:
                user_data = local_appdata / "Microsoft" / "Edge" / "User Data"
                roots.extend(user_data.glob(f"*/Extensions/{extension_id}"))
            elif "opera" in normalized_browser:
                roots.append(roaming_appdata / "Opera Software" / "Opera Stable" / "Extensions" / extension_id)

        if original_path.parent.exists():
            roots.append(original_path.parent)
        if original_path.parent.parent.exists():
            roots.append(original_path.parent.parent)

        dedup: list[Path] = []
        seen: set[str] = set()
        for path in roots:
            key = str(path).lower()
            if key in seen:
                continue
            seen.add(key)
            dedup.append(path)
        return dedup

    def _open_virustotal(self) -> None:
        """Abre o VirusTotal no navegador com o hash (se calculado) ou busca por nome."""
        row = self._selected_row()
        if row < 0:
            QMessageBox.warning(self, "Selecione um item", "Clique em uma linha antes de consultar no VirusTotal.")
            return

        item = self._items[row]
        if row in self._hashes:
            url = _VIRUSTOTAL_URL.format(sha256=self._hashes[row][1])
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
