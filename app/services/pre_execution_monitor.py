"""Monitor de pre-execucao que vigia pastas criticas via polling em thread dedicada.

Arquitetura:
  - PreExecutionMonitorService gerencia um threading.Thread de polling proprio.
  - A cada POLL_INTERVAL segundos, compara o estado atual das pastas monitoradas
    com o snapshot anterior para detectar arquivos novos.
  - Cada arquivo novo e analisado em sub-thread dedicada apos um breve delay
    para aguardar o termino da escrita (downloads incompletos, etc.).
  - O resultado e entregue via alert_callback, que deve ser thread-safe
    (p.ex. queue.Queue.put, que e atomico em CPython).
  - A interface faz polling da fila via QTimer e emite os alertas na thread Qt.
"""

from __future__ import annotations

import hashlib
import logging
import os
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Callable

from app.services.analyzer_context import ContextAnalyzer
from app.services.analyzer_hash import HashAnalyzer
from app.services.analyzer_static import StaticFileAnalyzer
from app.services.archive_inspector import ArchiveInspector
from app.services.pre_execution_models import PreExecutionAlert
from app.services.risk_engine import RiskEngine, RiskSignal
from app.services.shortcut_analyzer import ShortcutAnalyzer
from app.services.script_pattern_analyzer import ScriptPatternAnalyzer
from app.utils.logger import log_info, log_security_event, log_warning


# Extensoes monitoradas na deteccao de arquivos novos
_MONITORED_EXTENSIONS: frozenset[str] = frozenset({
    ".exe", ".dll", ".scr", ".com",
    ".bat", ".cmd", ".ps1", ".vbs",
    ".js", ".jse", ".wsf", ".hta", ".msi",
    ".lnk",
    ".zip", ".jar", ".apk", ".docm", ".xlsm", ".pptm",
})

# Extensoes de alta prioridade que recebem sinal extra de chegada em pastas de risco
_HIGH_PRIORITY_EXTENSIONS: frozenset[str] = frozenset({
    ".exe", ".bat", ".cmd", ".ps1", ".vbs",
    ".js", ".jse", ".wsf", ".scr", ".lnk", ".msi", ".hta",
})


def _resolve_watched_dirs() -> list[Path]:
    """Retorna as pastas criticas do usuario para monitoramento padrao em qualquer Windows."""
    home = Path.home()
    candidates = [
        home / "Downloads",
        home / "Desktop",
        home / "Documents",
        Path(os.environ.get("TEMP", str(home / "AppData" / "Local" / "Temp"))),
        Path(os.environ.get("TMP", "")),
    ]
    return [p for p in candidates if p.exists() and p.is_dir()]


class PreExecutionMonitorService:
    """Servico de monitoramento de pastas com analise pré-execucao em camadas.

    Pipeline de analise para cada arquivo novo detectado:
      1. StaticFileAnalyzer  — magic bytes, dupla extensao, entropia, ofuscacao
      2. ContextAnalyzer     — local de entrega (Downloads/Desktop/Temp)
      3. HashAnalyzer        — blacklist/whitelist local
      4. ShortcutAnalyzer    — atalhos .lnk com destinos perigosos
      5. ScriptPatternAnalyzer — padroes perigosos por tipo de script
      6. ArchiveInspector    — executaveis/scripts dentro de ZIPs
      7. Sinal de chegada    — localizacao de alto risco aumenta score
    """

    POLL_INTERVAL = 2.5      # Segundos entre checagens de cada pasta
    SETTLE_DELAY  = 1.5      # Aguarda arquivo terminar de ser escrito antes de analisar
    MAX_HEAD      = 65_536   # Bytes lidos para analise (cabecalho do arquivo)

    def __init__(
        self,
        logger: logging.Logger,
        *,
        data_dir: Path,
        alert_callback: Callable[[PreExecutionAlert], None],
        extra_dirs: list[Path] | None = None,
    ) -> None:
        self.logger = logger
        self.alert_callback = alert_callback

        # Motores de analise reutilizados entre arquivos
        self._risk_engine      = RiskEngine()
        self._static           = StaticFileAnalyzer()
        self._context          = ContextAnalyzer()
        self._hash             = HashAnalyzer(logger, data_dir)
        self._shortcut         = ShortcutAnalyzer()
        self._script           = ScriptPatternAnalyzer()
        self._archive          = ArchiveInspector()

        # Pastas monitoradas
        dirs = _resolve_watched_dirs()
        if extra_dirs:
            dirs.extend(d for d in extra_dirs if d.exists() and d.is_dir())
        self._watch_dirs: list[Path] = list(dict.fromkeys(dirs))  # Deduplica mantendo ordem

        # Estado interno (thread-safe via lock para _analyzed)
        self._known_files: dict[Path, set[Path]] = {}
        self._analyzed: set[Path] = set()
        self._analyzed_lock = threading.Lock()

        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    @property
    def watched_dirs(self) -> list[Path]:
        """Lista de pastas atualmente sob monitoramento."""
        return list(self._watch_dirs)

    def start(self) -> None:
        """Inicializa o polling em thread dedicada do sistema operacional."""
        if self._thread and self._thread.is_alive():
            return

        self._stop_event.clear()
        self._snapshot_all()

        self._thread = threading.Thread(
            target=self._run_loop,
            name="SentinelaPreExecMonitor",
            daemon=True,
        )
        self._thread.start()
        log_info(
            self.logger,
            f"[Pre-exec] Monitor ativo | pastas={[str(d) for d in self._watch_dirs]}",
        )

    def stop(self) -> None:
        """Para o polling de forma cooperativa."""
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=4.0)

    def add_directory(self, path: Path) -> None:
        """Adiciona uma pasta extra ao monitoramento em tempo real."""
        if path not in self._watch_dirs and path.exists():
            self._watch_dirs.append(path)
            self._snapshot_dir(path)

    # ──────────────────────────────────────────────────────────────────────────
    # Internos
    # ──────────────────────────────────────────────────────────────────────────

    def _snapshot_all(self) -> None:
        for directory in self._watch_dirs:
            self._snapshot_dir(directory)

    def _snapshot_dir(self, directory: Path) -> None:
        try:
            self._known_files[directory] = {
                item
                for item in directory.iterdir()
                if item.is_file() and item.suffix.lower() in _MONITORED_EXTENSIONS
            }
        except OSError:
            self._known_files[directory] = set()

    def _run_loop(self) -> None:
        while not self._stop_event.is_set():
            self._check_all_dirs()
            self._stop_event.wait(self.POLL_INTERVAL)

    def _check_all_dirs(self) -> None:
        for directory in self._watch_dirs:
            if not directory.is_dir():
                continue
            try:
                current = {
                    item
                    for item in directory.iterdir()
                    if item.is_file() and item.suffix.lower() in _MONITORED_EXTENSIONS
                }
            except OSError:
                continue

            known = self._known_files.get(directory, set())
            new_files = current - known
            self._known_files[directory] = current

            for file_path in new_files:
                with self._analyzed_lock:
                    already = file_path in self._analyzed
                if not already:
                    self._dispatch_analysis(file_path)

    def _dispatch_analysis(self, file_path: Path) -> None:
        """Agenda analise em sub-thread apos aguardar o arquivo estabilizar."""

        def _run() -> None:
            time.sleep(self.SETTLE_DELAY)
            if file_path.exists():
                self._analyze(file_path)

        threading.Thread(
            target=_run,
            name=f"PreExec-{file_path.stem[:24]}",
            daemon=True,
        ).start()

    def _analyze(self, file_path: Path) -> None:
        """Executa a pipeline de analise pre-execucao em camadas para um arquivo novo."""
        with self._analyzed_lock:
            if file_path in self._analyzed:
                return
            self._analyzed.add(file_path)

        try:
            stat = file_path.stat()
        except OSError:
            return

        extension = file_path.suffix.lower()
        file_size = stat.st_size

        try:
            head = file_path.read_bytes()[: self.MAX_HEAD]
        except OSError:
            head = b""

        sha256 = self._compute_sha256(file_path)
        signals: list[RiskSignal] = []
        modules_used: list[str] = []

        # Camada 1: Estatica (magic, nome, entropia, ofuscacao)
        s = self._static.analyze_file(
            file_path=file_path,
            extension=extension,
            file_size=file_size,
            head=head,
        )
        if s:
            signals.extend(s)
            modules_used.append("analyzer_static")

        # Camada 2: Contexto (Program Files confiavel, browser extension, entrega de payload)
        s = self._context.analyze_file_context(
            file_path=file_path,
            extension=extension,
            signature_publisher=None,  # Sem PE signature check na pre-execucao (custo alto)
        )
        if s:
            signals.extend(s)
            modules_used.append("analyzer_context")

        # Camada 3: Hash (blacklist/whitelist local)
        if sha256:
            s = self._hash.analyze(sha256)
            if s:
                signals.extend(s)
                modules_used.append("analyzer_hash")

        # Camada 4: Atalho LNK
        if extension == ".lnk":
            s = self._shortcut.analyze(file_path)
            if s:
                signals.extend(s)
                modules_used.append("shortcut_analyzer")

        # Camada 5: Padroes de script por tipo
        if extension in self._script.SUPPORTED_EXTENSIONS:
            s = self._script.analyze(file_path)
            if s:
                signals.extend(s)
                modules_used.append("script_pattern_analyzer")

        # Camada 6: Inspecao de arquivo compactado
        s = self._archive.analyze(file_path)
        if s:
            signals.extend(s)
            modules_used.append("archive_inspector")

        # Camada 7: Sinal de chegada em area de risco
        s = self._arrival_signals(file_path, extension)
        if s:
            signals.extend(s)

        assessment = self._risk_engine.assess(signals=signals)

        # Score > 19 = saiu da faixa limpa; gera alerta
        if assessment.score > 19:
            alert = PreExecutionAlert(
                file_path=file_path,
                score=assessment.score,
                risk_level=assessment.risk_level,
                recommended_action=assessment.recommended_action,
                reasons=assessment.reasons,
                categories=assessment.categories,
                timestamp=datetime.now(),
                analysis_modules=modules_used,
            )
            log_security_event(
                self.logger,
                f"[Pre-exec] {alert.severity_label} | score={assessment.score} | {file_path}",
            )
            try:
                self.alert_callback(alert)
            except Exception as error:
                log_warning(self.logger, f"[Pre-exec] Falha no callback de alerta: {error}")

    def _arrival_signals(self, file_path: Path, extension: str) -> list[RiskSignal]:
        """Sinais extras baseados no local onde o arquivo chegou."""
        if extension not in _HIGH_PRIORITY_EXTENSIONS:
            return []

        normalized = str(file_path).lower().replace("/", "\\")
        signals: list[RiskSignal] = []

        if "\\downloads\\" in normalized:
            signals.append(
                RiskSignal(
                    reason="Arquivo risco alto detectado recem-chegado em Downloads",
                    weight=16,
                    category="chegada_suspeita",
                    module="pre_execution_monitor",
                )
            )
        elif "\\desktop\\" in normalized:
            signals.append(
                RiskSignal(
                    reason="Arquivo risco alto detectado recem-chegado no Desktop",
                    weight=12,
                    category="chegada_suspeita",
                    module="pre_execution_monitor",
                )
            )
        elif "\\temp\\" in normalized or "\\appdata\\local\\temp\\" in normalized:
            signals.append(
                RiskSignal(
                    reason="Arquivo executavel/script surgiu em pasta Temp",
                    weight=22,
                    category="chegada_suspeita",
                    module="pre_execution_monitor",
                )
            )

        return signals

    def _compute_sha256(self, file_path: Path) -> str:
        try:
            h = hashlib.sha256()
            with file_path.open("rb") as fh:
                for chunk in iter(lambda: fh.read(65_536), b""):
                    h.update(chunk)
            return h.hexdigest()
        except OSError:
            return ""
