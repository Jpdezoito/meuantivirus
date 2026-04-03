"""Servico responsavel por diagnostico de saude e desempenho do PC."""

from __future__ import annotations

import logging
import platform
from datetime import datetime
from pathlib import Path
import time

import psutil

from app.services.file_scanner_service import ScanControl
from app.services.diagnostics_models import (
    DiagnosticIssue,
    DiagnosticPathError,
    HeavyProcessEntry,
    SystemDiagnosticsReport,
)
from app.services.file_scan_models import FileScanReport
from app.services.process_scan_models import ProcessScanReport
from app.services.startup_inspector_service import StartupInspectorService
from app.services.startup_scan_models import StartupScanReport
from app.utils.logger import log_info, log_warning


class DiagnosticsService:
    """Reune sinais de desempenho e saude geral sem atuar como scanner de bugs."""

    def __init__(self, logger: logging.Logger, startup_inspector: StartupInspectorService) -> None:
        self.logger = logger
        self.startup_inspector = startup_inspector

    def collect_system_summary(self) -> dict[str, str]:
        """Retorna um resumo simples do sistema operacional atual."""
        summary = {
            "system": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "machine": platform.machine(),
        }
        self.logger.info("Resumo de diagnostico gerado.")
        return summary

    def diagnose_system(
        self,
        *,
        startup_report: StartupScanReport | None = None,
        file_report: FileScanReport | None = None,
        process_report: ProcessScanReport | None = None,
        progress_callback: callable | None = None,
        scan_control: ScanControl | None = None,
    ) -> SystemDiagnosticsReport:
        """Coleta um panorama de desempenho e sinais simples de lentidao do PC."""
        if not self._await_scan_control(scan_control, progress_callback):
            return self._build_interrupted_report()

        self._emit_progress(progress_callback, "[Diagnostico] Coletando uso atual de CPU e memoria...")
        cpu_usage_percent = psutil.cpu_percent(interval=0.6)
        memory_snapshot = psutil.virtual_memory()

        if not self._await_scan_control(scan_control, progress_callback):
            return self._build_interrupted_report(cpu_usage_percent=cpu_usage_percent, memory_usage_percent=memory_snapshot.percent)

        self._emit_progress(progress_callback, "[Diagnostico] Coletando uso de disco e espaco livre...")
        disk_path = self._resolve_disk_reference()
        disk_snapshot = psutil.disk_usage(str(disk_path))

        if not self._await_scan_control(scan_control, progress_callback):
            return self._build_interrupted_report(
                cpu_usage_percent=cpu_usage_percent,
                memory_usage_percent=memory_snapshot.percent,
                disk_usage_percent=disk_snapshot.percent,
                free_disk_gb=round(disk_snapshot.free / (1024**3), 2),
                total_disk_gb=round(disk_snapshot.total / (1024**3), 2),
            )

        self._emit_progress(progress_callback, "[Diagnostico] Identificando processos mais pesados...")
        heavy_processes = self._collect_heavy_processes(scan_control, progress_callback)

        if not self._await_scan_control(scan_control, progress_callback):
            return self._build_interrupted_report(
                cpu_usage_percent=cpu_usage_percent,
                memory_usage_percent=memory_snapshot.percent,
                disk_usage_percent=disk_snapshot.percent,
                free_disk_gb=round(disk_snapshot.free / (1024**3), 2),
                total_disk_gb=round(disk_snapshot.total / (1024**3), 2),
                heavy_processes=heavy_processes,
            )

        self._emit_progress(progress_callback, "[Diagnostico] Avaliando programas de inicializacao...")
        current_startup_report = startup_report or self.startup_inspector.inspect_startup(
            progress_callback=progress_callback,
            scan_control=scan_control,
        )

        path_errors = self._collect_path_errors(file_report, process_report, current_startup_report)
        slowdown_signals = self._build_slowdown_signals(
            cpu_usage_percent,
            memory_snapshot.percent,
            disk_snapshot.percent,
            len(current_startup_report.results),
            heavy_processes,
        )
        issues = self._build_health_issues(
            cpu_usage_percent,
            memory_snapshot.percent,
            disk_snapshot.percent,
            disk_snapshot.free,
            len(current_startup_report.results),
            path_errors,
            slowdown_signals,
        )

        report = SystemDiagnosticsReport(
            generated_at=datetime.now(),
            cpu_usage_percent=cpu_usage_percent,
            memory_usage_percent=memory_snapshot.percent,
            disk_usage_percent=disk_snapshot.percent,
            free_disk_gb=round(disk_snapshot.free / (1024**3), 2),
            total_disk_gb=round(disk_snapshot.total / (1024**3), 2),
            startup_items_count=len(current_startup_report.results),
            interrupted=scan_control.is_cancelled() if scan_control is not None else False,
            startup_programs=[result.name for result in current_startup_report.results[:10]],
            heavy_processes=heavy_processes,
            slowdown_signals=slowdown_signals,
            path_errors=path_errors,
            issues=issues,
            startup_report_used=current_startup_report,
        )
        log_info(
            self.logger,
            (
                "Diagnostico do sistema concluido | "
                f"cpu={report.cpu_usage_percent:.1f}% | memoria={report.memory_usage_percent:.1f}% | "
                f"disco={report.disk_usage_percent:.1f}% | startup={report.startup_items_count}"
            ),
        )
        return report

    def _collect_heavy_processes(
        self,
        scan_control: ScanControl | None,
        progress_callback: callable | None,
    ) -> list[HeavyProcessEntry]:
        """Seleciona os processos que mais consomem CPU e memoria no momento."""
        process_samples: list[HeavyProcessEntry] = []

        for process in psutil.process_iter(["pid", "name", "memory_percent", "exe"]):
            if not self._await_scan_control(scan_control, progress_callback):
                break

            try:
                cpu_percent = process.cpu_percent(interval=None)
                memory_percent = float(process.info.get("memory_percent") or 0.0)
                executable_path = process.info.get("exe")
                process_samples.append(
                    HeavyProcessEntry(
                        name=process.info.get("name") or f"PID {process.pid}",
                        pid=int(process.info.get("pid") or process.pid),
                        cpu_usage_percent=cpu_percent,
                        memory_usage_percent=memory_percent,
                        executable_path=Path(executable_path) if executable_path else None,
                    )
                )
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        # Faz uma segunda leitura curta para obter amostras de CPU mais realistas.
        psutil.cpu_percent(interval=0.3)
        refreshed_samples: list[HeavyProcessEntry] = []
        for sample in process_samples:
            if not self._await_scan_control(scan_control, progress_callback):
                break

            try:
                process = psutil.Process(sample.pid)
                refreshed_samples.append(
                    HeavyProcessEntry(
                        name=sample.name,
                        pid=sample.pid,
                        cpu_usage_percent=process.cpu_percent(interval=0.0),
                        memory_usage_percent=sample.memory_usage_percent,
                        executable_path=sample.executable_path,
                    )
                )
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                refreshed_samples.append(sample)

        refreshed_samples.sort(
            key=lambda item: (item.cpu_usage_percent + item.memory_usage_percent),
            reverse=True,
        )
        return refreshed_samples[:5]

    def _collect_path_errors(
        self,
        file_report: FileScanReport | None,
        process_report: ProcessScanReport | None,
        startup_report: StartupScanReport,
    ) -> list[DiagnosticPathError]:
        """Agrupa erros simples de acesso e caminhos invalidos vistos na sessao."""
        path_errors: list[DiagnosticPathError] = []

        if file_report is not None:
            for error in file_report.errors:
                path_errors.append(
                    DiagnosticPathError(
                        source="Arquivos",
                        location=str(error.path),
                        message=error.message,
                    )
                )

        if process_report is not None:
            for error in process_report.errors:
                path_errors.append(
                    DiagnosticPathError(
                        source="Processos",
                        location=error.process_name,
                        message=error.message,
                    )
                )

        for error in startup_report.errors:
            path_errors.append(
                DiagnosticPathError(
                    source="Inicializacao",
                    location=error.source,
                    message=error.message,
                )
            )

        return path_errors[:20]

    def _build_slowdown_signals(
        self,
        cpu_usage_percent: float,
        memory_usage_percent: float,
        disk_usage_percent: float,
        startup_items_count: int,
        heavy_processes: list[HeavyProcessEntry],
    ) -> list[str]:
        """Monta sinais simples de lentidao percebida com base nas leituras atuais."""
        signals: list[str] = []

        if cpu_usage_percent >= 85:
            signals.append("Uso de CPU muito alto no momento, o que pode causar travamentos temporarios.")
        if memory_usage_percent >= 85:
            signals.append("Uso de memoria elevado, com risco de perda de responsividade e troca intensa em disco.")
        if disk_usage_percent >= 90:
            signals.append("Disco muito ocupado, reduzindo espaco livre e impactando o desempenho geral.")
        if startup_items_count >= 12:
            signals.append("Muitos itens iniciando com o Windows, o que pode tornar a inicializacao mais lenta.")
        if heavy_processes:
            heaviest = heavy_processes[0]
            if heaviest.cpu_usage_percent >= 40 or heaviest.memory_usage_percent >= 10:
                signals.append(
                    f"Processo com alto impacto detectado: {heaviest.name} (PID {heaviest.pid})."
                )

        if not signals:
            signals.append("Nenhum sinal forte de lentidao foi detectado nesta amostra do sistema.")
        return signals

    def _build_health_issues(
        self,
        cpu_usage_percent: float,
        memory_usage_percent: float,
        disk_usage_percent: float,
        free_disk_bytes: int,
        startup_items_count: int,
        path_errors: list[DiagnosticPathError],
        slowdown_signals: list[str],
    ) -> list[DiagnosticIssue]:
        """Transforma leituras e sinais em achados estruturados para UI e relatorio."""
        issues: list[DiagnosticIssue] = []

        if cpu_usage_percent >= 85:
            issues.append(DiagnosticIssue("CPU", "alto", "Uso atual de CPU acima de 85%."))
        elif cpu_usage_percent >= 65:
            issues.append(DiagnosticIssue("CPU", "medio", "Uso atual de CPU acima de 65%."))

        if memory_usage_percent >= 85:
            issues.append(DiagnosticIssue("Memoria", "alto", "Uso atual de memoria acima de 85%."))
        elif memory_usage_percent >= 70:
            issues.append(DiagnosticIssue("Memoria", "medio", "Uso atual de memoria acima de 70%."))

        free_disk_gb = free_disk_bytes / (1024**3)
        if disk_usage_percent >= 90 or free_disk_gb <= 15:
            issues.append(DiagnosticIssue("Disco", "alto", "Pouco espaco livre ou uso de disco excessivo."))
        elif disk_usage_percent >= 80 or free_disk_gb <= 30:
            issues.append(DiagnosticIssue("Disco", "medio", "Espaco livre em disco reduzido."))

        if startup_items_count >= 12:
            issues.append(DiagnosticIssue("Inicializacao", "medio", "Quantidade alta de programas iniciando com o sistema."))

        if path_errors:
            issues.append(
                DiagnosticIssue(
                    "Acesso a caminhos",
                    "medio",
                    f"Foram observados {len(path_errors)} erros simples de acesso ou caminhos invalidos nos scans.",
                )
            )

        if not issues:
            issues.append(DiagnosticIssue("Saude geral", "baixo", slowdown_signals[0]))
        else:
            log_warning(self.logger, f"Diagnostico encontrou {len(issues)} achados relevantes de saude do sistema.")

        return issues

    def _resolve_disk_reference(self) -> Path:
        """Escolhe um caminho valido para medir o uso do disco principal."""
        project_drive = Path.cwd().anchor or "C:\\"
        return Path(project_drive)

    def _emit_progress(self, progress_callback: callable | None, message: str) -> None:
        """Encaminha mensagens de progresso apenas quando a UI solicitar."""
        if progress_callback is not None:
            progress_callback(message)

    def _await_scan_control(
        self,
        scan_control: ScanControl | None,
        progress_callback: callable | None,
    ) -> bool:
        """Respeita pausa/cancelamento cooperativo durante o diagnostico."""
        if scan_control is None:
            return True

        while scan_control.is_paused():
            self._emit_progress(progress_callback, "[Diagnostico] Coleta pausada...")
            time.sleep(0.15)
            if scan_control.is_cancelled():
                return False

        return not scan_control.is_cancelled()

    def _build_interrupted_report(
        self,
        cpu_usage_percent: float = 0.0,
        memory_usage_percent: float = 0.0,
        disk_usage_percent: float = 0.0,
        free_disk_gb: float = 0.0,
        total_disk_gb: float = 0.0,
        heavy_processes: list[HeavyProcessEntry] | None = None,
    ) -> SystemDiagnosticsReport:
        """Retorna um relatorio parcial quando o usuario interrompe o diagnostico."""
        return SystemDiagnosticsReport(
            generated_at=datetime.now(),
            cpu_usage_percent=cpu_usage_percent,
            memory_usage_percent=memory_usage_percent,
            disk_usage_percent=disk_usage_percent,
            free_disk_gb=free_disk_gb,
            total_disk_gb=total_disk_gb,
            startup_items_count=0,
            interrupted=True,
            startup_programs=[],
            heavy_processes=list(heavy_processes or []),
            slowdown_signals=["Diagnostico interrompido pelo usuario antes da coleta completa."],
            path_errors=[],
            issues=[DiagnosticIssue("Diagnostico", "baixo", "Execucao interrompida manualmente pelo usuario.")],
            startup_report_used=None,
        )
