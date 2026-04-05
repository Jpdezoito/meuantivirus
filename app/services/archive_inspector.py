"""Inspeciona arquivos compactados em busca de conteudo suspeito sem extrair nada."""

from __future__ import annotations

import re
import zipfile
from pathlib import Path

from app.services.risk_engine import RiskSignal


class ArchiveInspector:
    """Lista entradas internas de arquivos ZIP para detectar payloads suspeitos.

    Nenhum arquivo e extraido: apenas os metadados das entradas (nomes, tamanhos)
    sao lidos, tornando a operacao segura mesmo para arquivos maliciosos.
    Formatos nao-ZIP (.rar, .7z, .gz) sao sinalizados apenas quando vierem
    de pastas de alto risco, sem tentativa de parsing.
    """

    INSPECTED_ZIP_EXTENSIONS: frozenset[str] = frozenset({
        ".zip", ".jar", ".apk", ".docm", ".xlsm", ".pptm",
    })

    # Extensoes consideradas perigosas nomeadas dentro do arquivo
    DANGEROUS_INTERNAL: frozenset[str] = frozenset({
        ".exe", ".dll", ".scr", ".com",
        ".bat", ".cmd", ".ps1", ".vbs",
        ".js", ".jse", ".wsf", ".hta", ".msi", ".lnk",
    })

    DOUBLE_EXT_PATTERN = re.compile(
        r"\.(pdf|jpg|jpeg|png|gif|txt|doc|docx|xls|xlsx)\.(exe|bat|cmd|ps1|vbs|js|scr|lnk)$",
        re.IGNORECASE,
    )

    # Limites de seguranca para evitar lentidao em arquivos grandes
    MAX_ENTRIES_TO_INSPECT = 500
    SUSPICIOUS_ENTRY_COUNT_THRESHOLD = 4_000

    def analyze(self, file_path: Path) -> list[RiskSignal]:
        """Retorna sinais de risco baseados no conteudo do arquivo compactado."""
        signals: list[RiskSignal] = []
        extension = file_path.suffix.lower()

        if extension not in self.INSPECTED_ZIP_EXTENSIONS:
            return signals

        if not zipfile.is_zipfile(str(file_path)):
            # Arquivo com extensao ZIP mas conteudo invalido = suspeito
            signals.append(
                RiskSignal(
                    reason="Arquivo com extensao .zip/.jar mas cabecalho invalido (possivel mascaramento)",
                    weight=20,
                    category="masquerading",
                    module="archive_inspector",
                )
            )
            return signals

        try:
            with zipfile.ZipFile(str(file_path), "r") as archive:
                entries = archive.infolist()
        except (zipfile.BadZipFile, OSError):
            return signals

        total = len(entries)
        if total > self.SUSPICIOUS_ENTRY_COUNT_THRESHOLD:
            signals.append(
                RiskSignal(
                    reason=f"Arquivo compactado com numero anomalo de entradas ({total}) — possivel ZIP bomb",
                    weight=24,
                    category="zip_bomb",
                    module="archive_inspector",
                )
            )
            return signals

        dangerous_names: list[str] = []
        double_ext_found = False

        for entry in entries[: self.MAX_ENTRIES_TO_INSPECT]:
            name = entry.filename.lower().replace("/", "\\")
            suffix = "." + name.rsplit(".", 1)[-1] if "." in name else ""

            if suffix in self.DANGEROUS_INTERNAL:
                dangerous_names.append(entry.filename)

            if self.DOUBLE_EXT_PATTERN.search(name):
                double_ext_found = True

        if double_ext_found:
            signals.append(
                RiskSignal(
                    reason="Arquivo compactado contem entrada com dupla extensao suspeita",
                    weight=28,
                    category="masquerading",
                    module="archive_inspector",
                )
            )

        if dangerous_names:
            sample = dangerous_names[0]
            weight = 22 if len(dangerous_names) == 1 else 30
            signals.append(
                RiskSignal(
                    reason=(
                        f"Arquivo compactado contem {len(dangerous_names)} entrada(s) executavel/script "
                        f"(ex: {sample})"
                    ),
                    weight=weight,
                    category="payload_oculto",
                    module="archive_inspector",
                )
            )

        return signals
