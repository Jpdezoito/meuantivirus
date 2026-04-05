"""Servico de diagnostico para processos suspeitos em execucao."""

from __future__ import annotations

from collections.abc import Callable
import logging
from pathlib import Path
import re
import time

import psutil

from app.core.heuristics import HeuristicEngine
from app.core.risk import ThreatClassification
from app.services.file_scanner_service import ScanControl
from app.services.process_scan_models import ProcessScanError, ProcessScanReport, ProcessScanResult
from app.services.analyzer_behavior import ProcessBehaviorAnalyzer
from app.services.risk_engine import RiskEngine
from app.utils.logger import log_info, log_security_event, log_warning


class ProcessMonitorService:
    """Analisa os processos do sistema e sinaliza comportamentos suspeitos."""

    KNOWN_VIRTUAL_PROCESS_NAMES = {
        "system idle process",
        "system",
        "registry",
        "memcompression",
    }

    TEMPORARY_DIRECTORY_MARKERS = (
        "\\appdata\\local\\temp\\",
        "\\windows\\temp\\",
        "\\temp\\",
        "\\tmp\\",
    )

    CPU_SAMPLE_COUNT = 3
    CPU_SAMPLE_INTERVAL = 0.35
    HIGH_CPU_THRESHOLD = 70.0
    HIGH_MEMORY_THRESHOLD = 20.0
    STRANGE_NAME_PATTERN = re.compile(r"^[a-z0-9]{8,}$", re.IGNORECASE)

    def __init__(self, logger: logging.Logger, heuristic_engine: HeuristicEngine) -> None:
        self.logger = logger
        self.heuristic_engine = heuristic_engine
        self.behavior_analyzer = ProcessBehaviorAnalyzer()
        self.risk_engine = RiskEngine()

    def scan_processes(
        self,
        progress_callback: Callable[[str], None] | None = None,
        scan_control: ScanControl | None = None,
    ) -> ProcessScanReport:
        """Varre os processos ativos e retorna apenas os que apresentam sinais de risco."""
        self._emit_progress(progress_callback, "[Processos] Coletando lista de processos ativos...")

        tracked_processes: list[dict[str, object]] = []
        errors: list[ProcessScanError] = []

        for process in psutil.process_iter(attrs=["pid", "name"]):
            if not self._await_scan_control(scan_control, progress_callback, "[Processos] Analise pausada..."):
                break

            process_name = process.info.get("name") or "desconhecido"
            pid = int(process.info.get("pid") or 0)

            executable_path = self._safe_get_executable_path(process, process_name, pid, errors)
            tracked_processes.append(
                {
                    "process": process,
                    "pid": pid,
                    "name": process_name,
                    "executable_path": executable_path,
                    "cpu_samples": [],
                    "memory_samples": [],
                }
            )

        inspected_processes = len(tracked_processes)
        log_info(self.logger, f"Processos coletados para analise inicial: {inspected_processes}")
        self._emit_progress(
            progress_callback,
            f"[Processos] {inspected_processes} processos encontrados para observacao.",
        )

        for tracked_process in tracked_processes:
            if not self._await_scan_control(scan_control, progress_callback, "[Processos] Analise pausada..."):
                break

            process = tracked_process["process"]
            try:
                process.cpu_percent(None)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        for sample_index in range(self.CPU_SAMPLE_COUNT):
            if not self._await_scan_control(scan_control, progress_callback, "[Processos] Analise pausada..."):
                break

            time.sleep(self.CPU_SAMPLE_INTERVAL)
            self._collect_resource_sample(tracked_processes, errors)
            self._emit_progress(
                progress_callback,
                (
                    "[Processos] Amostra de uso coletada "
                    f"({sample_index + 1}/{self.CPU_SAMPLE_COUNT})."
                ),
            )

        results: list[ProcessScanResult] = []
        for tracked_process in tracked_processes:
            if not self._await_scan_control(scan_control, progress_callback, "[Processos] Analise pausada..."):
                break

            result = self._build_process_result(tracked_process)
            if result is None:
                continue

            results.append(result)
            label = "malicioso" if result.final_classification == ThreatClassification.MALICIOUS else "suspeito"
            log_security_event(
                self.logger,
                (
                    f"Processo {label} detectado: {result.name} ({result.pid}) | "
                    f"classificacao={result.final_classification.value} | risco={result.initial_risk_level}"
                ),
            )
            self._emit_progress(
                progress_callback,
                (
                    "[Processos] Processo suspeito encontrado: "
                    f"{result.name} (PID {result.pid}) | classe={result.final_classification.value} | risco={result.initial_risk_level}"
                ),
            )

        interrupted = scan_control.is_cancelled() if scan_control is not None else False

        report = ProcessScanReport(
            inspected_processes=inspected_processes,
            suspicious_processes=len(results),
            interrupted=interrupted,
            results=results,
            errors=errors,
        )
        log_info(
            self.logger,
            (
                "Analise de processos concluida | "
                f"processos={report.inspected_processes} | suspeitos={report.suspicious_processes} | erros={len(report.errors)}"
            ),
        )
        self._emit_progress(
            progress_callback,
            (
                "[Processos] Analise concluida. "
                f"Processos avaliados: {report.inspected_processes}. "
                f"Suspeitos: {report.suspicious_processes}."
            ),
        )
        return report

    def _safe_get_executable_path(
        self,
        process: psutil.Process,
        process_name: str,
        pid: int,
        errors: list[ProcessScanError],
    ) -> Path | None:
        """Obtém o caminho do executável sem interromper a analise em caso de falha."""
        try:
            executable = process.exe()
        except psutil.AccessDenied as error:
            self._register_error(pid, process_name, f"Acesso negado ao caminho do executavel. | detalhe: {error}", errors)
            return None
        except (psutil.NoSuchProcess, psutil.ZombieProcess):
            return None
        except OSError as error:
            self._register_error(pid, process_name, f"Falha ao consultar caminho do executavel. | detalhe: {error}", errors)
            return None

        if not executable:
            return None

        return Path(executable)

    def _collect_resource_sample(
        self,
        tracked_processes: list[dict[str, object]],
        errors: list[ProcessScanError],
    ) -> None:
        """Coleta uma amostra de CPU e memoria dos processos acompanhados."""
        for tracked_process in tracked_processes:
            process = tracked_process["process"]
            pid = int(tracked_process["pid"])
            process_name = str(tracked_process["name"])

            try:
                cpu_usage = float(process.cpu_percent(None))
                memory_usage = float(process.memory_percent())
            except psutil.AccessDenied as error:
                self._register_error(pid, process_name, f"Acesso negado ao coletar uso de recursos. | detalhe: {error}", errors)
                continue
            except (psutil.NoSuchProcess, psutil.ZombieProcess):
                continue
            except OSError as error:
                self._register_error(pid, process_name, f"Falha ao coletar uso de recursos. | detalhe: {error}", errors)
                continue

            tracked_process["cpu_samples"].append(cpu_usage)
            tracked_process["memory_samples"].append(memory_usage)

    def _build_process_result(
        self,
        tracked_process: dict[str, object],
    ) -> ProcessScanResult | None:
        """Aplica heuristicas simples e produz o resultado padronizado quando houver alerta."""
        process_name = str(tracked_process["name"] or "desconhecido")
        pid = int(tracked_process["pid"])
        executable_path = tracked_process["executable_path"]
        cpu_samples = list(tracked_process["cpu_samples"])
        memory_samples = list(tracked_process["memory_samples"])

        if process_name.lower() in self.KNOWN_VIRTUAL_PROCESS_NAMES:
            return None

        cpu_average = sum(cpu_samples) / len(cpu_samples) if cpu_samples else 0.0
        memory_average = sum(memory_samples) / len(memory_samples) if memory_samples else 0.0

        normalized_path = ""
        has_invalid_path = False
        if executable_path is not None:
            normalized_path = str(executable_path).lower().replace("/", "\\")
            has_invalid_path = not executable_path.exists()

        signature_publisher = self.heuristic_engine.resolve_signature_publisher(executable_path)

        evaluation = self.heuristic_engine.evaluate_process(
            process_name=process_name,
            executable_path=executable_path,
            has_invalid_path=has_invalid_path,
            is_temporary_location=self._is_temporary_location(normalized_path),
            has_strange_name=self._has_strange_name(process_name),
            has_sustained_high_cpu=self._has_sustained_high_cpu(cpu_samples),
            has_sustained_high_memory=self._has_sustained_high_memory(memory_samples),
            signature_publisher=signature_publisher,
        )

        behavior_signals = self.behavior_analyzer.analyze_process(
            process_name=process_name,
            executable_path=executable_path,
            cpu_samples=cpu_samples,
            memory_samples=memory_samples,
            command_line=self._safe_get_cmdline(tracked_process["process"]),
            parent_name=self._safe_get_parent_name(tracked_process["process"]),
        )
        assessment = self.risk_engine.assess(base_score=evaluation.score, signals=behavior_signals)
        combined_reasons = list(dict.fromkeys([*evaluation.reasons, *[signal.reason for signal in behavior_signals]]))
        combined_reasons.append(f"Acao recomendada: {assessment.recommended_action.value}")
        final_evaluation = self.heuristic_engine.build_custom_evaluation(assessment.score, combined_reasons)

        if final_evaluation.classification == ThreatClassification.TRUSTED:
            return None

        return ProcessScanResult(
            name=process_name,
            pid=pid,
            executable_path=executable_path,
            cpu_usage_percent=cpu_average,
            memory_usage_percent=memory_average,
            heuristic_score=final_evaluation.score,
            heuristic_summary=final_evaluation.explanation,
            alert_reason=final_evaluation.explanation,
            initial_risk_level=final_evaluation.risk_level,
            final_classification=final_evaluation.classification,
            classification_reasons=list(final_evaluation.reasons),
            recommended_action=assessment.recommended_action.value,
            threat_category=self._extract_process_category(combined_reasons),
            analysis_module="process_monitor",
            detected_signals=list(combined_reasons),
        )

    def _has_strange_name(self, process_name: str) -> bool:
        """Tenta identificar nomes muito artificiais ou aleatorios."""
        normalized_name = Path(process_name).stem.lower()
        if len(normalized_name) < 8:
            return False

        if not self.STRANGE_NAME_PATTERN.fullmatch(normalized_name):
            return False

        digit_count = sum(character.isdigit() for character in normalized_name)
        vowel_count = sum(character in "aeiou" for character in normalized_name)
        unique_ratio = len(set(normalized_name)) / len(normalized_name)

        has_many_digits = digit_count >= 3
        has_almost_no_vowels = vowel_count == 0 and len(normalized_name) >= 10
        has_high_randomness = unique_ratio >= 0.9 and digit_count >= 2

        return has_many_digits or has_almost_no_vowels or has_high_randomness

    def _has_sustained_high_cpu(self, cpu_samples: list[float]) -> bool:
        """Marca processos que mantiveram CPU alta durante varias amostras."""
        if len(cpu_samples) < self.CPU_SAMPLE_COUNT:
            return False

        high_samples = sum(sample >= self.HIGH_CPU_THRESHOLD for sample in cpu_samples)
        average = sum(cpu_samples) / len(cpu_samples)
        return high_samples >= 2 and average >= self.HIGH_CPU_THRESHOLD

    def _has_sustained_high_memory(self, memory_samples: list[float]) -> bool:
        """Marca processos com uso alto de memoria ao longo das amostras."""
        if len(memory_samples) < self.CPU_SAMPLE_COUNT:
            return False

        high_samples = sum(sample >= self.HIGH_MEMORY_THRESHOLD for sample in memory_samples)
        average = sum(memory_samples) / len(memory_samples)
        return high_samples >= 2 and average >= self.HIGH_MEMORY_THRESHOLD

    def _is_temporary_location(self, normalized_path: str) -> bool:
        """Verifica se o executavel esta em diretorios temporarios conhecidos."""
        return any(marker in normalized_path for marker in self.TEMPORARY_DIRECTORY_MARKERS)

    def _register_error(
        self,
        pid: int | None,
        process_name: str,
        message: str,
        errors: list[ProcessScanError],
    ) -> None:
        """Registra erros de acesso sem interromper a verificacao."""
        errors.append(
            ProcessScanError(
                pid=pid,
                process_name=process_name,
                message=message,
            )
        )
        log_warning(self.logger, f"Processo {process_name} ({pid}) | {message}")

    def _safe_get_cmdline(self, process: psutil.Process) -> str:
        """Le cmdline do processo sem interromper o fluxo quando houver bloqueio."""
        try:
            return " ".join(process.cmdline())
        except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess, OSError):
            return ""

    def _safe_get_parent_name(self, process: psutil.Process) -> str:
        """Retorna nome do processo pai quando disponivel."""
        try:
            parent = process.parent()
            if parent is None:
                return ""
            return parent.name() or ""
        except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess, OSError):
            return ""

    def _extract_process_category(self, reasons: list[str]) -> str:
        lowered = " | ".join(reasons).lower()
        if "ransom" in lowered or "wiper" in lowered:
            return "ransomware/wiper"
        if "fileless" in lowered or "encodedcommand" in lowered:
            return "fileless"
        if "cryptojacking" in lowered or "cpu elevada" in lowered:
            return "cryptojacker"
        if "trojan" in lowered or "dropper" in lowered:
            return "trojan"
        return "comportamento_anomalo"

    def _emit_progress(
        self,
        progress_callback: Callable[[str], None] | None,
        message: str,
    ) -> None:
        """Envia progresso sem criar acoplamento com a interface."""
        if progress_callback is not None:
            progress_callback(message)

    def _await_scan_control(
        self,
        scan_control: ScanControl | None,
        progress_callback: Callable[[str], None] | None,
        pause_message: str,
    ) -> bool:
        """Respeita pausa/cancelamento cooperativo durante a verificacao."""
        if scan_control is None:
            return True

        while scan_control.is_paused():
            self._emit_progress(progress_callback, pause_message)
            time.sleep(0.15)
            if scan_control.is_cancelled():
                return False

        return not scan_control.is_cancelled()
