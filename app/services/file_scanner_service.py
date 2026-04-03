"""Servico de verificacao basica de arquivos potencialmente sensiveis."""

from __future__ import annotations

from collections.abc import Callable, Iterator
import hashlib
import logging
from pathlib import Path
import threading
import time

from app.core.heuristics import HeuristicEngine
from app.core.risk import ThreatClassification
from app.services.file_scan_models import FileScanError, FileScanReport, FileScanResult, RiskLevel
from app.utils.logger import log_error, log_info, log_security_event, log_warning


class ScanControl:
    """Coordena pausa e cancelamento cooperativo da varredura de arquivos."""

    def __init__(self) -> None:
        self._pause_event = threading.Event()
        self._cancel_event = threading.Event()

    def request_pause(self) -> None:
        self._pause_event.set()

    def request_resume(self) -> None:
        self._pause_event.clear()

    def request_cancel(self) -> None:
        self._cancel_event.set()
        self._pause_event.clear()

    def is_paused(self) -> bool:
        return self._pause_event.is_set()

    def is_cancelled(self) -> bool:
        return self._cancel_event.is_set()


class FileScannerService:
    """Executa uma varredura inicial em busca de arquivos suspeitos."""

    SKIP_DIRECTORY_NAMES = {
        ".git",
        ".venv",
        "__pycache__",
        "env",
        "node_modules",
        "venv",
    }

    SENSITIVE_EXTENSIONS = {
        ".exe",
        ".dll",
        ".bat",
        ".cmd",
        ".ps1",
        ".vbs",
        ".js",
        ".jar",
        ".scr",
    }

    TEMPORARY_DIRECTORY_MARKERS = (
        "\\appdata\\local\\temp\\",
        "\\windows\\temp\\",
        "\\temp\\",
        "\\tmp\\",
    )

    UNUSUAL_DIRECTORY_MARKERS = (
        "\\downloads\\",
        "\\desktop\\",
        "\\documents\\",
        "\\appdata\\roaming\\",
        "\\programdata\\",
        "\\recycler\\",
        "\\$recycle.bin\\",
    )

    def __init__(self, logger: logging.Logger, heuristic_engine: HeuristicEngine) -> None:
        self.logger = logger
        self.heuristic_engine = heuristic_engine

    def scan_path(
        self,
        target: Path,
        progress_callback: Callable[[str], None] | None = None,
        scan_label: str = "Verificacao de arquivos",
        scan_control: ScanControl | None = None,
        stats_callback: Callable[[int, int], None] | None = None,
    ) -> FileScanReport:
        """Percorre a pasta recursivamente e retorna apenas arquivos sinalizados."""
        normalized_target = target.expanduser().resolve()
        log_info(self.logger, f"Varredura solicitada para: {normalized_target}")
        self._emit_progress(
            progress_callback,
            f"[Scanner] Iniciando analise da pasta: {normalized_target}",
        )

        results: list[FileScanResult] = []
        errors: list[FileScanError] = []
        scanned_files = 0
        self._emit_stats(stats_callback, scanned_files, len(results))

        if not normalized_target.exists() or not normalized_target.is_dir():
            error = FileScanError(
                path=normalized_target,
                message="O caminho informado nao existe ou nao e uma pasta valida.",
            )
            errors.append(error)
            log_error(self.logger, error.message)
            self._emit_progress(progress_callback, f"[Scanner] {error.message}")
            return FileScanReport(
                target_directory=normalized_target,
                scanned_files=0,
                flagged_files=0,
                interrupted=False,
                scan_label=scan_label,
                results=[],
                errors=errors,
            )

        for file_path in self._iter_files(
            normalized_target,
            errors,
            progress_callback=progress_callback,
            root_directory=normalized_target,
            scan_control=scan_control,
        ):
            if not self._await_scan_control(scan_control, progress_callback):
                break

            scanned_files += 1
            result = self._analyze_file(file_path, errors)

            if scanned_files % 50 == 0:
                self._emit_progress(
                    progress_callback,
                    f"[Scanner] Progresso parcial: {scanned_files} arquivos verificados.",
                )
                self._emit_stats(stats_callback, scanned_files, len(results))

            if result is None:
                continue

            results.append(result)
            log_security_event(
                self.logger,
                f"Arquivo sinalizado: {result.path} | risco={result.initial_risk_level}",
            )
            self._emit_progress(
                progress_callback,
                (
                    "[Scanner] Item suspeito encontrado: "
                    f"{result.path} | risco={result.initial_risk_level}"
                ),
            )
            self._emit_stats(stats_callback, scanned_files, len(results))

        interrupted = scan_control.is_cancelled() if scan_control is not None else False

        log_info(
            self.logger,
            (
                "Varredura concluida | arquivos analisados="
                f"{scanned_files} | arquivos sinalizados={len(results)} | erros={len(errors)}"
            ),
        )
        self._emit_progress(
            progress_callback,
            (
                "[Scanner] Analise interrompida. "
                if interrupted
                else "[Scanner] Analise finalizada. "
            )
            + (
                f"Arquivos verificados: {scanned_files}. "
                f"Itens suspeitos: {len(results)}."
            ),
        )
        self._emit_stats(stats_callback, scanned_files, len(results))

        return FileScanReport(
            target_directory=normalized_target,
            scanned_files=scanned_files,
            flagged_files=len(results),
            interrupted=interrupted,
            scan_label=scan_label,
            results=results,
            errors=errors,
        )

    def _iter_files(
        self,
        directory: Path,
        errors: list[FileScanError],
        progress_callback: Callable[[str], None] | None = None,
        root_directory: Path | None = None,
        scan_control: ScanControl | None = None,
    ) -> Iterator[Path]:
        """Percorre diretorios com pathlib e registra problemas de permissao."""
        progress_root = root_directory or directory
        self._emit_progress(
            progress_callback,
            f"[Scanner] Abrindo pasta: {self._format_progress_path(directory, progress_root)}",
        )

        if not self._await_scan_control(scan_control, progress_callback):
            return

        try:
            children = sorted(directory.iterdir(), key=lambda entry: entry.name.lower())
        except PermissionError as error:
            self._register_permission_error(directory, error, errors)
            self._emit_progress(
                progress_callback,
                f"[Scanner] Permissao negada ao acessar: {self._format_progress_path(directory, progress_root)}",
            )
            return
        except OSError as error:
            self._register_access_error(directory, error, errors)
            self._emit_progress(
                progress_callback,
                f"[Scanner] Falha ao acessar pasta: {self._format_progress_path(directory, progress_root)}",
            )
            return

        for child in children:
            if not self._await_scan_control(scan_control, progress_callback):
                return

            if child.is_dir():
                if self._should_skip_directory(child, progress_root):
                    self._emit_progress(
                        progress_callback,
                        (
                            "[Scanner] Pasta ignorada automaticamente: "
                            f"{self._format_progress_path(child, progress_root)}"
                        ),
                    )
                    continue

                yield from self._iter_files(
                    child,
                    errors,
                    progress_callback=progress_callback,
                    root_directory=progress_root,
                    scan_control=scan_control,
                )
                continue

            if child.is_file():
                yield child

    def _analyze_file(
        self,
        file_path: Path,
        errors: list[FileScanError],
    ) -> FileScanResult | None:
        """Analisa um arquivo e retorna resultado somente quando houver alerta."""
        try:
            file_size = file_path.stat().st_size
            sha256_hash = self._calculate_sha256(file_path)
        except PermissionError as error:
            self._register_permission_error(file_path, error, errors)
            return None
        except OSError as error:
            self._register_access_error(file_path, error, errors)
            return None

        extension = file_path.suffix.lower()
        alert_reason, risk_level, heuristic_score, final_classification, classification_reasons = self._build_alert(file_path, extension)

        if alert_reason is None or risk_level is None:
            return None

        return FileScanResult(
            path=file_path,
            size=file_size,
            sha256=sha256_hash,
            extension=extension or "sem_extensao",
            heuristic_score=heuristic_score,
            heuristic_summary=alert_reason,
            alert_reason=alert_reason,
            initial_risk_level=risk_level,
            final_classification=final_classification,
            classification_reasons=classification_reasons,
        )

    def _calculate_sha256(self, file_path: Path) -> str:
        """Calcula o hash SHA-256 em blocos para reduzir uso de memoria."""
        digest = hashlib.sha256()

        with file_path.open("rb") as file_handle:
            for chunk in iter(lambda: file_handle.read(1024 * 1024), b""):
                digest.update(chunk)

        return digest.hexdigest()

    def _build_alert(
        self,
        file_path: Path,
        extension: str,
    ) -> tuple[str | None, RiskLevel | None, int, ThreatClassification | None, list[str]]:
        """Aplica heuristicas simples para marcar arquivos com risco inicial."""
        if extension not in self.SENSITIVE_EXTENSIONS:
            return None, None, 0, None, []

        normalized_path = str(file_path).lower().replace("/", "\\")
        evaluation = self.heuristic_engine.evaluate_file(
            path=file_path,
            extension=extension,
            is_sensitive_extension=True,
            is_temporary_location=self._is_temporary_location(normalized_path),
            is_unusual_location=self._is_unusual_location(normalized_path),
            # Para manter performance na varredura de arquivos, assinatura fica opcional aqui.
            signature_publisher=None,
        )

        if evaluation.classification == ThreatClassification.TRUSTED:
            return None, None, 0, None, []

        return (
            evaluation.explanation,
            evaluation.risk_level,
            evaluation.score,
            evaluation.classification,
            list(evaluation.reasons),
        )

    def _is_temporary_location(self, normalized_path: str) -> bool:
        """Verifica se o arquivo esta em uma pasta temporaria conhecida."""
        return any(marker in normalized_path for marker in self.TEMPORARY_DIRECTORY_MARKERS)

    def _is_unusual_location(self, normalized_path: str) -> bool:
        """Verifica pastas incomuns para armazenar executaveis em uso cotidiano."""
        return any(marker in normalized_path for marker in self.UNUSUAL_DIRECTORY_MARKERS)

    def _should_skip_directory(self, directory: Path, root_directory: Path) -> bool:
        """Ignora arvores de desenvolvimento e cache para reduzir falsos positivos."""
        if directory == root_directory:
            return False

        return directory.name.lower() in self.SKIP_DIRECTORY_NAMES

    def _await_scan_control(
        self,
        scan_control: ScanControl | None,
        progress_callback: Callable[[str], None] | None,
    ) -> bool:
        """Aguarda retomada quando pausado e encerra cedo quando cancelado."""
        if scan_control is None:
            return True

        pause_announced = False
        while True:
            if scan_control.is_cancelled():
                return False

            if not scan_control.is_paused():
                if pause_announced:
                    self._emit_progress(progress_callback, "[Scanner] Varredura retomada pelo usuario.")
                return True

            if not pause_announced:
                self._emit_progress(progress_callback, "[Scanner] Varredura pausada pelo usuario.")
                pause_announced = True

            time.sleep(0.1)

    def _emit_stats(
        self,
        stats_callback: Callable[[int, int], None] | None,
        scanned_files: int,
        flagged_files: int,
    ) -> None:
        """Entrega contadores parciais para a interface sem depender de parsing textual."""
        if stats_callback is not None:
            stats_callback(scanned_files, flagged_files)

    def _register_permission_error(
        self,
        target: Path,
        error: PermissionError,
        errors: list[FileScanError],
    ) -> None:
        """Padroniza o registro de falhas de permissao durante a leitura."""
        message = f"Permissao negada ao acessar: {target}"
        errors.append(FileScanError(path=target, message=message))
        log_warning(self.logger, f"{message} | detalhe: {error}")

    def _register_access_error(
        self,
        target: Path,
        error: OSError,
        errors: list[FileScanError],
    ) -> None:
        """Registra outros erros de sistema de arquivos sem interromper a varredura."""
        message = f"Falha ao acessar caminho durante a analise: {target}"
        errors.append(FileScanError(path=target, message=message))
        log_warning(self.logger, f"{message} | detalhe: {error}")

    def _emit_progress(
        self,
        progress_callback: Callable[[str], None] | None,
        message: str,
    ) -> None:
        """Envia mensagens de progresso sem acoplar o scanner a uma interface especifica."""
        if progress_callback is not None:
            progress_callback(message)

    def _format_progress_path(self, path: Path, root_directory: Path) -> str:
        """Resume caminhos abaixo da raiz analisada para tornar o log legivel."""
        try:
            relative_path = path.relative_to(root_directory)
        except ValueError:
            return str(path)

        relative_text = str(relative_path)
        if relative_text == ".":
            return str(root_directory)
        return relative_text
