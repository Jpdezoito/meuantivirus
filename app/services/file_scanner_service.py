"""Servico de verificacao basica de arquivos potencialmente sensiveis."""

from __future__ import annotations

from collections.abc import Callable, Iterator
import hashlib
import logging
from pathlib import Path
import re
import threading
import time

from app.core.heuristics import HeuristicEngine, HeuristicEvaluation
from app.core.risk import ThreatClassification
from app.services.file_scan_models import FileScanError, FileScanReport, FileScanResult, RiskLevel
from app.services.virustotal_service import VirusTotalService
from app.services.behavior_monitor import BehaviorMonitor
from app.services.analyzer_context import ContextAnalyzer
from app.services.analyzer_hash import HashAnalyzer
from app.services.analyzer_static import StaticFileAnalyzer
from app.services.risk_engine import ResponseAction, RiskEngine, RiskSignal
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


class _DeepFileScanResult:
    """Resultado interno da verificacao profunda aplicada aos candidatos suspeitos."""

    def __init__(
        self,
        *,
        score: int,
        risk_level: RiskLevel,
        classification: ThreatClassification,
        reasons: list[str],
        explanation: str,
        trusted_publisher: str | None,
    ) -> None:
        self.score = score
        self.risk_level = risk_level
        self.classification = classification
        self.reasons = reasons
        self.explanation = explanation
        self.trusted_publisher = trusted_publisher


class FileScannerService:
    """Executa uma varredura inicial em busca de arquivos suspeitos."""

    SCRIPT_MARKERS: dict[str, tuple[str, ...]] = {
        ".ps1": (
            "invoke-expression",
            "iex ",
            "downloadstring",
            "invoke-webrequest",
            "frombase64string",
            "start-process",
            "set-mppreference",
            "add-mppreference",
            "new-scheduledtask",
            "-encodedcommand",
        ),
        ".bat": (
            "powershell -",
            "bitsadmin",
            "certutil -urlcache",
            "regsvr32",
            "rundll32",
            "schtasks",
            "curl ",
            "wget ",
        ),
        ".cmd": (
            "powershell -",
            "bitsadmin",
            "certutil -urlcache",
            "regsvr32",
            "rundll32",
            "schtasks",
            "curl ",
            "wget ",
        ),
        ".js": (
            "wscript.shell",
            "activexobject",
            "powershell",
            "downloadfile",
            "msxml2.xmlhttp",
            "adodb.stream",
        ),
        ".vbs": (
            "createobject",
            "wscript.shell",
            "adodb.stream",
            "msxml2.xmlhttp",
            "powershell",
        ),
    }
    EXECUTABLE_EXTENSIONS = {".exe", ".dll", ".jar", ".scr"}
    SCRIPT_EXTENSIONS = {".ps1", ".vbs", ".bat", ".cmd", ".js"}
    DOUBLE_EXTENSION_PATTERN = re.compile(
        r"\.(pdf|jpg|jpeg|png|gif|txt|doc|docx|xls|xlsx)\.(exe|scr|bat|cmd|js|vbs|ps1)$",
        re.IGNORECASE,
    )

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

    def __init__(self, logger: logging.Logger, heuristic_engine: HeuristicEngine, use_virustotal: bool = True, use_behavior_monitor: bool = True) -> None:
        self.logger = logger
        self.heuristic_engine = heuristic_engine
        self.static_analyzer = StaticFileAnalyzer()
        self.context_analyzer = ContextAnalyzer()
        self.hash_analyzer = HashAnalyzer(logger)
        self.risk_engine = RiskEngine()
        self.virustotal: VirusTotalService | None = None
        self.behavior_monitor: BehaviorMonitor | None = None
        
        if use_virustotal:
            try:
                self.virustotal = VirusTotalService(logger=logger)
                # Criar arquivo de configuração template se não existir
                from app.services.virustotal_service import create_virustotal_config_template
                create_virustotal_config_template()
            except Exception as e:
                log_warning(logger, f"VirusTotal não disponível: {e}")
        
        if use_behavior_monitor:
            try:
                self.behavior_monitor = BehaviorMonitor(logger=logger)
            except Exception as e:
                log_warning(logger, f"Behavior monitor não disponível: {e}")

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
        
        # Mostra status dos módulos de inteligência
        if self.virustotal and self.virustotal.api_key:
            self._emit_progress(progress_callback, "[VirusTotal] Modulo ativo — arquivos suspeitos serao consultados online.")
        else:
            self._emit_progress(progress_callback, "[VirusTotal] Inativo — configure a chave em app/data/virustotal_config.json.")
        
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
            result = self._analyze_file(file_path, errors, progress_callback=progress_callback)

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

        # Resumo final com status de cada módulo
        if len(results) == 0:
            self._emit_progress(progress_callback, "[Scanner] Nenhum arquivo suspeito encontrado — VirusTotal nao foi acionado.")
        else:
            self._emit_progress(progress_callback, f"[Scanner] {len(results)} arquivo(s) suspeito(s) — VirusTotal foi consultado para cada um.")

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
        progress_callback: Callable[[str], None] | None = None,
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
        initial_evaluation = self._build_alert(file_path, extension)

        if initial_evaluation is None:
            return None

        self._emit_progress(
            progress_callback,
            f"[Scanner] Verificacao profunda em andamento: {file_path}",
        )
        deep_result = self._perform_deep_verification(file_path, extension, initial_evaluation, errors, sha256_hash=sha256_hash)
        if deep_result is None:
            self._emit_progress(
                progress_callback,
                f"[Scanner] Item descartado apos verificacao profunda: {file_path}",
            )
            return None

        return FileScanResult(
            path=file_path,
            size=file_size,
            sha256=sha256_hash,
            extension=extension or "sem_extensao",
            heuristic_score=deep_result.score,
            heuristic_summary=initial_evaluation.explanation,
            alert_reason=deep_result.explanation,
            initial_risk_level=deep_result.risk_level,
            final_classification=deep_result.classification,
            classification_reasons=deep_result.reasons,
            deep_scan_performed=True,
            deep_scan_summary=deep_result.explanation,
            trusted_publisher=deep_result.trusted_publisher,
            recommended_action=self.risk_engine.assess(base_score=deep_result.score).recommended_action.value,
            threat_category=self._extract_primary_category(deep_result.reasons),
            analysis_module="file_scanner",
            detected_signals=list(deep_result.reasons),
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
    ) -> HeuristicEvaluation | None:
        """Aplica heuristicas simples para marcar arquivos com risco inicial."""
        if extension not in self.SENSITIVE_EXTENSIONS:
            return None

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
            return None

        return evaluation

    def _perform_deep_verification(
        self,
        file_path: Path,
        extension: str,
        initial_evaluation: HeuristicEvaluation,
        errors: list[FileScanError],
        sha256_hash: str | None = None,
    ) -> _DeepFileScanResult | None:
        """Refina um alerta inicial com sinais mais caros antes de exibir o item."""
        trusted_publisher = self.heuristic_engine.resolve_signature_publisher(file_path)
        normalized_path = str(file_path).lower().replace("/", "\\")
        deep_signals = self._collect_deep_signals(
            file_path,
            extension,
            errors,
            sha256_hash=sha256_hash,
            signature_publisher=trusted_publisher,
        )

        reevaluated = self.heuristic_engine.evaluate_file(
            path=file_path,
            extension=extension,
            is_sensitive_extension=True,
            is_temporary_location=self._is_temporary_location(normalized_path),
            is_unusual_location=self._is_unusual_location(normalized_path),
            signature_publisher=trusted_publisher,
        )
        risk_assessment = self.risk_engine.assess(base_score=reevaluated.score, signals=deep_signals)
        deep_reasons = [signal.reason for signal in deep_signals]
        combined_reasons = list(dict.fromkeys([*reevaluated.reasons, *initial_evaluation.reasons, *deep_reasons]))
        final_score = max(0, risk_assessment.score)
        
        # Verifica se o hash está na whitelist de confiança
        if sha256_hash:
            final_score, combined_reasons = self.heuristic_engine.apply_trusted_hash_reduction(
                final_score, combined_reasons, sha256_hash
            )
            
            # Consulta VirusTotal se disponível
            if self.virustotal and final_score >= 20:  # Só consulta se arquivo ainda tem risco considerável
                try:
                    log_info(self.logger, f"[VirusTotal] Consultando reputacao: {file_path.name} ({sha256_hash[:16]}...)")
                    vt_result = self.virustotal.check_file_reputation(sha256_hash)
                    if vt_result.get("found"):
                        vt_delta = self.virustotal.calculate_vt_score_delta(vt_result)
                        final_score = max(0, final_score + vt_delta)
                        detections = vt_result.get("detections", 0)
                        total = vt_result.get("total_vendors", "?")
                        verdict = "SEGURO" if detections == 0 else f"{detections}/{total} motores detectaram"
                        combined_reasons.append(
                            f"VirusTotal: {verdict}"
                        )
                        log_info(self.logger, f"[VirusTotal] {file_path.name}: {verdict} | score ajustado para {final_score}")
                    elif not vt_result.get("error"):
                        log_info(self.logger, f"[VirusTotal] {file_path.name}: hash nao encontrado na base")
                except Exception as e:
                    log_warning(self.logger, f"Erro ao consultar VirusTotal: {e}")
        
        final_evaluation = self.heuristic_engine.build_custom_evaluation(
            final_score,
            list(dict.fromkeys([*combined_reasons, f"Acao recomendada: {risk_assessment.recommended_action.value}"])),
        )

        if final_evaluation.classification == ThreatClassification.TRUSTED:
            return None

        return _DeepFileScanResult(
            score=final_evaluation.score,
            risk_level=final_evaluation.risk_level,
            classification=final_evaluation.classification,
            reasons=list(final_evaluation.reasons),
            explanation=final_evaluation.explanation,
            trusted_publisher=trusted_publisher,
        )

    def _collect_deep_signals(
        self,
        file_path: Path,
        extension: str,
        errors: list[FileScanError],
        sha256_hash: str | None = None,
        signature_publisher: str | None = None,
    ) -> list[RiskSignal]:
        """Inspeciona cabecalho e trechos iniciais de candidatos suspeitos."""
        signals: list[RiskSignal] = []

        if self.DOUBLE_EXTENSION_PATTERN.search(file_path.name):
            signals.append(
                RiskSignal(
                    reason="Arquivo usa dupla extensao para simular documento confiavel",
                    weight=20,
                    category="masquerading",
                    module="file_scanner",
                )
            )

        try:
            with file_path.open("rb") as file_handle:
                head = file_handle.read(4096)
        except PermissionError as error:
            self._register_permission_error(file_path, error, errors)
            return signals
        except OSError as error:
            self._register_access_error(file_path, error, errors)
            return signals

        file_size = file_path.stat().st_size if file_path.exists() else 0
        signals.extend(
            self.static_analyzer.analyze_file(
                file_path=file_path,
                extension=extension,
                file_size=file_size,
                head=head,
            )
        )
        signals.extend(
            self.context_analyzer.analyze_file_context(
                file_path=file_path,
                extension=extension,
                signature_publisher=signature_publisher,
            )
        )

        if extension in self.EXECUTABLE_EXTENSIONS:
            if head.startswith(b"MZ"):
                signals.append(
                    RiskSignal(
                        reason="Cabecalho executavel PE valido detectado",
                        weight=0,
                        category="inspecao_pe",
                        module="file_scanner",
                    )
                )
            else:
                signals.append(
                    RiskSignal(
                        reason="Extensao executavel sem cabecalho PE esperado",
                        weight=20,
                        category="payload_oculto",
                        module="file_scanner",
                    )
                )

        if extension in self.SCRIPT_EXTENSIONS:
            script_reasons, script_delta = self._inspect_script_markers(head, extension)
            for reason in script_reasons:
                signals.append(
                    RiskSignal(
                        reason=reason,
                        weight=script_delta,
                        category="script_suspeito",
                        module="file_scanner",
                    )
                )

        if sha256_hash:
            hash_signals = self.hash_analyzer.analyze(sha256_hash)
            signals.extend(hash_signals)

        return signals

    def _extract_primary_category(self, reasons: list[str]) -> str:
        """Extrai uma categoria resumida com base nas razoes consolidadas."""
        lowered = " | ".join(reasons).lower()
        if "ransom" in lowered or "wiper" in lowered:
            return "ransomware/wiper"
        if "trojan" in lowered or "payload" in lowered:
            return "trojan/dropper"
        if "script" in lowered or "encodedcommand" in lowered:
            return "script_suspeito"
        if "browser" in lowered or "extensao" in lowered:
            return "browser_extension"
        if "hash" in lowered:
            return "reputacao_hash"
        return "desconhecido"

    def _inspect_script_markers(self, head: bytes, extension: str) -> tuple[list[str], int]:
        """Busca sinais comuns de script ofensivo em uma janela pequena do arquivo."""
        lowered = head.decode("utf-8", errors="ignore").lower()
        markers = self.SCRIPT_MARKERS.get(extension, ())
        matched = sorted({marker for marker in markers if marker in lowered})
        if not matched:
            return [], 0

        return [f"Marcadores de script potencialmente abusivo: {', '.join(matched)}"], 10 if len(matched) == 1 else 20

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

    def analyze_running_process(self, process_id: int, process_name: str) -> dict | None:
        """Analisa o comportamento de um processo em execução para detecção em tempo real.
        
        Retorna dicionário com resultado da análise ou None se monitor não disponível.
        """
        if not self.behavior_monitor:
            return None
        
        try:
            risk = self.behavior_monitor.analyze_process_behavior(process_id, process_name)
            if risk is None:
                return None
            
            return {
                "process_id": risk.process_id,
                "process_name": risk.process_name,
                "behavioral_score": risk.behavioral_score,
                "risk_level": str(risk.risk_level),
                "behaviors": risk.detected_behaviors,
                "explanation": risk.explanation,
                "injection": risk.injection_attempt,
                "encryption": risk.encryption_pattern,
                "av_evasion": risk.av_evasion_attempt,
                "registry_mod": risk.registry_modification_attempt,
                "network_suspicious": risk.network_suspicious,
            }
        except Exception as e:
            log_warning(self.logger, f"Erro ao analisar comportamento do processo {process_id}: {e}")
            return None

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
