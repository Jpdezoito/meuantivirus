"""Servico de leitura e diagnostico das fontes de inicializacao do Windows."""

from __future__ import annotations

from collections.abc import Callable
import csv
import logging
import os
from pathlib import Path
import re
import subprocess
import sys
import time

from app.core.heuristics import HeuristicEngine
from app.core.risk import RiskLevel, ThreatClassification
from app.services.file_scanner_service import ScanControl
from app.services.startup_scan_models import StartupScanError, StartupScanReport, StartupScanResult
from app.utils.logger import log_info, log_security_event, log_warning

if sys.platform == "win32":
    import winreg
else:
    winreg = None


class StartupInspectorService:
    """Centraliza a leitura das principais fontes de inicializacao automatica."""

    REGISTRY_LOCATIONS = (
        ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Run"),
        ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        ("HKLM", r"Software\Microsoft\Windows\CurrentVersion\Run"),
        ("HKLM", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        ("HKLM", r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
        ("HKLM", r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce"),
    )

    STARTUP_TASK_PATTERNS = (
        "at logon",
        "at startup",
        "on startup",
        "na inicializacao",
        "na inicialização",
        "ao fazer logon",
        "na inicializacao do sistema",
        "na inicialização do sistema",
    )

    TEMP_MARKERS = (
        "\\appdata\\local\\temp\\",
        "\\windows\\temp\\",
        "\\temp\\",
        "\\tmp\\",
    )

    SUSPICIOUS_COMMAND_MARKERS = (
        "powershell",
        "cmd.exe",
        "wscript",
        "cscript",
        "mshta",
        "rundll32",
    )

    KNOWN_IGNORED_STARTUP_FILES = {
        "desktop.ini",
    }

    PATH_PATTERN = re.compile(
        r'"([^\"]+)"|([A-Za-z]:\\[^\r\n]+?\.(?:exe|dll|bat|cmd|ps1|vbs|js|jar|scr|lnk))',
        re.IGNORECASE,
    )

    def __init__(self, logger: logging.Logger, heuristic_engine: HeuristicEngine) -> None:
        self.logger = logger
        self.heuristic_engine = heuristic_engine

    def inspect_startup(
        self,
        progress_callback: Callable[[str], None] | None = None,
        scan_control: ScanControl | None = None,
    ) -> StartupScanReport:
        """Le as principais fontes de inicializacao e classifica o risco inicial."""
        self._emit_progress(progress_callback, "[Inicializacao] Iniciando leitura das fontes de startup do Windows...")

        results: list[StartupScanResult] = []
        errors: list[StartupScanError] = []
        inspected_items = 0

        if self._await_scan_control(scan_control, progress_callback):
            folder_results, folder_inspected = self._read_user_startup_folder(errors, progress_callback, scan_control)
            results.extend(folder_results)
            inspected_items += folder_inspected
        if self._await_scan_control(scan_control, progress_callback):
            folder_results, folder_inspected = self._read_global_startup_folder(errors, progress_callback, scan_control)
            results.extend(folder_results)
            inspected_items += folder_inspected
        if self._await_scan_control(scan_control, progress_callback):
            registry_results, registry_inspected = self._read_registry_entries(errors, progress_callback, scan_control)
            results.extend(registry_results)
            inspected_items += registry_inspected
        if self._await_scan_control(scan_control, progress_callback):
            task_results, tasks_inspected = self._read_scheduled_tasks(errors, progress_callback, scan_control)
            results.extend(task_results)
            inspected_items += tasks_inspected

        suspicious_items = sum(result.risk_level != RiskLevel.LOW for result in results)
        interrupted = scan_control.is_cancelled() if scan_control is not None else False
        report = StartupScanReport(
            inspected_items=inspected_items,
            suspicious_items=suspicious_items,
            interrupted=interrupted,
            results=results,
            errors=errors,
        )

        log_info(
            self.logger,
            (
                "Verificacao de inicializacao concluida | "
                f"itens={report.inspected_items} | suspeitos={report.suspicious_items} | erros={len(report.errors)}"
            ),
        )
        self._emit_progress(
            progress_callback,
            (
                "[Inicializacao] Leitura interrompida. "
                if interrupted
                else "[Inicializacao] Leitura concluida. "
            )
            + (
                f"Itens avaliados: {report.inspected_items}. "
                f"Suspeitos: {report.suspicious_items}."
            ),
        )
        return report

    def _read_user_startup_folder(
        self,
        errors: list[StartupScanError],
        progress_callback: Callable[[str], None] | None,
        scan_control: ScanControl | None,
    ) -> tuple[list[StartupScanResult], int]:
        """Le a pasta Startup do usuario atual."""
        startup_dir = Path(os.environ.get("APPDATA", "")) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"
        self._emit_progress(progress_callback, f"[Inicializacao] Lendo pasta Startup do usuario: {startup_dir}")
        return self._read_startup_folder(
            directory=startup_dir,
            origin="Pasta Startup do usuario",
            errors=errors,
            scan_control=scan_control,
        )

    def _read_global_startup_folder(
        self,
        errors: list[StartupScanError],
        progress_callback: Callable[[str], None] | None,
        scan_control: ScanControl | None,
    ) -> tuple[list[StartupScanResult], int]:
        """Le a pasta Startup global, quando acessivel."""
        startup_dir = Path(os.environ.get("ProgramData", "")) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"
        self._emit_progress(progress_callback, f"[Inicializacao] Lendo pasta Startup global: {startup_dir}")
        return self._read_startup_folder(
            directory=startup_dir,
            origin="Pasta Startup global",
            errors=errors,
            scan_control=scan_control,
        )

    def _read_startup_folder(
        self,
        directory: Path,
        origin: str,
        errors: list[StartupScanError],
        scan_control: ScanControl | None,
    ) -> tuple[list[StartupScanResult], int]:
        """Le atalhos e arquivos presentes em uma pasta de startup."""
        if not directory.exists():
            return [], 0

        try:
            entries = sorted(directory.iterdir(), key=lambda item: item.name.lower())
        except PermissionError as error:
            self._register_error(origin, f"Permissao negada ao ler a pasta. | detalhe: {error}", errors)
            return [], 0
        except OSError as error:
            self._register_error(origin, f"Falha ao ler a pasta. | detalhe: {error}", errors)
            return [], 0

        results: list[StartupScanResult] = []
        inspected_items = 0
        for entry in entries:
            if not self._await_scan_control(scan_control):
                break

            if not entry.is_file():
                continue

            if entry.name.lower() in self.KNOWN_IGNORED_STARTUP_FILES:
                continue

            inspected_items += 1

            result = self._build_result(
                name=entry.name,
                origin=origin,
                command=str(entry),
                item_type="startup_folder",
            )
            if result is None:
                continue
            results.append(result)
            self._log_suspicious_startup_item(result)

        return results, inspected_items

    def _read_registry_entries(
        self,
        errors: list[StartupScanError],
        progress_callback: Callable[[str], None] | None,
        scan_control: ScanControl | None,
    ) -> tuple[list[StartupScanResult], int]:
        """Le as principais chaves Run e RunOnce do Registro do Windows."""
        if winreg is None:
            return [], 0

        self._emit_progress(progress_callback, "[Inicializacao] Lendo entradas de Run e RunOnce no Registro...")
        results: list[StartupScanResult] = []
        inspected_items = 0

        registry_roots = {
            "HKCU": winreg.HKEY_CURRENT_USER,
            "HKLM": winreg.HKEY_LOCAL_MACHINE,
        }

        for root_name, subkey in self.REGISTRY_LOCATIONS:
            if not self._await_scan_control(scan_control, progress_callback):
                break

            try:
                with winreg.OpenKey(registry_roots[root_name], subkey) as registry_key:
                    value_count = winreg.QueryInfoKey(registry_key)[1]
                    for index in range(value_count):
                        if not self._await_scan_control(scan_control, progress_callback):
                            break

                        value_name, value_data, _ = winreg.EnumValue(registry_key, index)
                        if not value_name and not value_data:
                            continue

                        inspected_items += 1

                        result = self._build_result(
                            name=value_name or "(padrao)",
                            origin=f"Registro {root_name}\\{subkey}",
                            command=str(value_data),
                            item_type="registry_run",
                        )
                        if result is None:
                            continue
                        results.append(result)
                        self._log_suspicious_startup_item(result)
            except FileNotFoundError:
                continue
            except PermissionError as error:
                self._register_error(
                    f"Registro {root_name}\\{subkey}",
                    f"Permissao negada ao ler chave do Registro. | detalhe: {error}",
                    errors,
                )
            except OSError as error:
                self._register_error(
                    f"Registro {root_name}\\{subkey}",
                    f"Falha ao ler chave do Registro. | detalhe: {error}",
                    errors,
                )

        return results, inspected_items

    def _read_scheduled_tasks(
        self,
        errors: list[StartupScanError],
        progress_callback: Callable[[str], None] | None,
        scan_control: ScanControl | None,
    ) -> tuple[list[StartupScanResult], int]:
        """Le tarefas agendadas relacionadas a logon ou startup em modo best effort."""
        self._emit_progress(progress_callback, "[Inicializacao] Consultando tarefas agendadas de startup...")

        try:
            completed_process = subprocess.run(
                ["schtasks", "/query", "/fo", "csv", "/v"],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                check=False,
                timeout=30,
            )
        except (OSError, subprocess.SubprocessError) as error:
            self._register_error("Tarefas Agendadas", f"Falha ao consultar tarefas agendadas. | detalhe: {error}", errors)
            return [], 0

        if completed_process.returncode != 0:
            self._register_error(
                "Tarefas Agendadas",
                f"Comando schtasks retornou codigo {completed_process.returncode}: {completed_process.stderr.strip()}",
                errors,
            )
            return [], 0

        lines = [line for line in completed_process.stdout.splitlines() if line.strip()]
        if not lines:
            return [], 0

        reader = csv.DictReader(lines)
        results: list[StartupScanResult] = []
        inspected_items = 0

        for row in reader:
            if not self._await_scan_control(scan_control, progress_callback):
                break

            task_name = self._first_existing_value(row, "TaskName", "Nome da Tarefa")
            schedule_type = self._first_existing_value(row, "Schedule Type", "Tipo de Agendamento")
            task_to_run = self._first_existing_value(row, "Task To Run", "Tarefa a Executar")

            if not task_name or not self._is_startup_task(schedule_type):
                continue

            inspected_items += 1

            result = self._build_result(
                name=task_name,
                origin="Tarefas Agendadas",
                command=task_to_run or "comando_indisponivel",
                item_type="scheduled_task",
            )
            if result is None:
                continue
            results.append(result)
            self._log_suspicious_startup_item(result)

        return results, inspected_items

    def _build_result(
        self,
        name: str,
        origin: str,
        command: str,
        item_type: str,
    ) -> StartupScanResult | None:
        """Aplica heuristicas simples e monta o resultado padronizado do item."""
        normalized_command = command.lower().replace("/", "\\")
        executable_path = self._extract_possible_path(command)
        signature_publisher = self.heuristic_engine.resolve_signature_publisher(executable_path)
        evaluation = self.heuristic_engine.evaluate_startup(
            name=name,
            command=command,
            item_type=item_type,
            is_temporary_location=any(marker in normalized_command for marker in self.TEMP_MARKERS),
            uses_suspicious_interpreter=any(
                marker in normalized_command for marker in self.SUSPICIOUS_COMMAND_MARKERS
            ),
            is_run_once=item_type == "registry_run" and "runonce" in origin.lower(),
            has_missing_path=executable_path is not None and not executable_path.exists(),
            executable_path=executable_path,
            signature_publisher=signature_publisher,
        )

        if evaluation.classification == ThreatClassification.TRUSTED:
            return None

        return StartupScanResult(
            name=name,
            origin=origin,
            command=command,
            item_type=item_type,
            heuristic_score=evaluation.score,
            heuristic_summary=evaluation.explanation,
            risk_level=evaluation.risk_level,
            flag_reason=evaluation.explanation,
            executable_path=executable_path,
            final_classification=evaluation.classification,
            classification_reasons=list(evaluation.reasons),
        )

    def _extract_possible_path(self, command: str) -> Path | None:
        """Tenta extrair um caminho local inicial de um comando de startup."""
        cleaned_command = command.strip()
        if not cleaned_command:
            return None

        if Path(cleaned_command).exists():
            return Path(cleaned_command)

        if cleaned_command.startswith('"'):
            closing_index = cleaned_command.find('"', 1)
            if closing_index > 1:
                return Path(cleaned_command[1:closing_index])

        regex_match = self.PATH_PATTERN.search(cleaned_command)
        if regex_match is not None:
            matched_path = regex_match.group(1) or regex_match.group(2)
            if matched_path:
                return Path(matched_path.strip())

        token = cleaned_command.split(" ")[0]
        if ":\\" in token or token.startswith("\\"):
            return Path(token)

        return None

    def _first_existing_value(self, row: dict[str, str], *headers: str) -> str:
        """Retorna a primeira coluna encontrada entre alternativas de idioma."""
        for header in headers:
            value = row.get(header)
            if value:
                return value.strip()
        return ""

    def _is_startup_task(self, schedule_type: str) -> bool:
        """Identifica tarefas disparadas no logon ou inicializacao do sistema."""
        normalized_schedule_type = (schedule_type or "").lower()
        return any(pattern in normalized_schedule_type for pattern in self.STARTUP_TASK_PATTERNS)

    def _register_error(
        self,
        source: str,
        message: str,
        errors: list[StartupScanError],
    ) -> None:
        """Registra falhas de leitura sem interromper a verificacao inteira."""
        errors.append(StartupScanError(source=source, message=message))
        log_warning(self.logger, f"Inicializacao | {source} | {message}")

    def _log_suspicious_startup_item(self, result: StartupScanResult) -> None:
        """Registra no log itens com nivel de risco acima do minimo."""
        if result.risk_level == RiskLevel.LOW:
            return

        log_security_event(
            self.logger,
            f"Item de inicializacao sinalizado: {result.name} | origem={result.origin} | risco={result.risk_level}",
        )

    def _emit_progress(
        self,
        progress_callback: Callable[[str], None] | None,
        message: str,
    ) -> None:
        """Envia mensagens de progresso sem acoplamento com a interface."""
        if progress_callback is not None:
            progress_callback(message)

    def _await_scan_control(
        self,
        scan_control: ScanControl | None,
        progress_callback: Callable[[str], None] | None = None,
    ) -> bool:
        """Respeita pausa/cancelamento cooperativo durante a leitura de startup."""
        if scan_control is None:
            return True

        while scan_control.is_paused():
            self._emit_progress(progress_callback, "[Inicializacao] Leitura pausada...")
            time.sleep(0.15)
            if scan_control.is_cancelled():
                return False

        return not scan_control.is_cancelled()
