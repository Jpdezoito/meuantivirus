"""Bridge de integracao para consumo do SentinelaPC por navegadores Electron."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import logging
from pathlib import Path
import threading
from typing import Any

from app.core.config import APP_VERSION, build_settings, ensure_runtime_directories
from app.core.heuristics import HeuristicEngine
from app.core.risk import ThreatClassification
from app.data.database import initialize_database
from app.services.file_scanner_service import FileScannerService
from app.services.url_threat_service import UrlThreatService
from app.utils.logger import configure_logging, log_error, log_info, log_warning


class AntivirusBridge:
    """Expoe uma API local padronizada para o processo principal do Electron."""

    API_VERSION = "1.0.0"
    SUSPICIOUS_FILE_EXTENSIONS = {
        ".exe",
        ".dll",
        ".bat",
        ".cmd",
        ".ps1",
        ".vbs",
        ".js",
        ".jar",
        ".scr",
        ".msi",
        ".com",
    }

    DOUBLE_EXTENSION_SUFFIXES = {
        ".pdf",
        ".doc",
        ".docx",
        ".xls",
        ".xlsx",
        ".txt",
        ".jpg",
        ".jpeg",
        ".png",
        ".gif",
    }

    def __init__(self, installation_path: str | Path | None = None) -> None:
        self._started_at = datetime.now(timezone.utc)
        self._lock = threading.Lock()
        self._ready = False
        self._init_error: str | None = None
        self._installation_path = Path(installation_path).expanduser().resolve() if installation_path else None

        self.settings = None
        self.paths = None
        self.logger: logging.Logger | None = None
        self._integration_logger: logging.Logger | None = None
        self.heuristic_engine: HeuristicEngine | None = None
        self.file_scanner: FileScannerService | None = None
        self.url_threat_service: UrlThreatService | None = None

        self._initialize()

    def _initialize(self) -> None:
        """Inicializa infraestrutura minima para chamadas externas com logs detalhados."""
        try:
            if self._installation_path is not None:
                self._validate_installation_path(self._installation_path)

            self.settings = build_settings()
            self.paths = self.settings.paths
            ensure_runtime_directories(self.paths)

            self.logger = configure_logging(self.settings)
            self._integration_logger = self.logger.getChild("integration")
            initialize_database(self.paths.database_file)

            self.heuristic_engine = HeuristicEngine()
            self.file_scanner = FileScannerService(
                self.logger,
                self.heuristic_engine,
                use_virustotal=False,
                use_behavior_monitor=False,
            )
            self.url_threat_service = UrlThreatService(data_dir=self.paths.data_dir)

            self._ready = True
            log_info(self.logger, "[Bridge] Integracao com navegador inicializada com sucesso.")
        except Exception as error:
            self._ready = False
            self._init_error = str(error)
            fallback_logger = logging.getLogger("sentinelapc.bridge")
            fallback_logger.setLevel(logging.INFO)
            fallback_logger.exception("Falha ao inicializar bridge de integracao")

    def _validate_installation_path(self, installation_path: Path) -> None:
        """Valida se o caminho fornecido pelo navegador parece uma instalacao do SentinelaPC."""
        if not installation_path.exists():
            raise FileNotFoundError(f"Caminho de instalacao nao encontrado: {installation_path}")

        required_entries = ("main.py", "app", "requirements.txt")
        missing = [name for name in required_entries if not (installation_path / name).exists()]
        if missing:
            raise FileNotFoundError(
                "Caminho de instalacao invalido para SentinelaPC. Ausente: " + ", ".join(missing)
            )

    def execute(self, command: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Roteia comandos vindos do Electron para funcoes seguras e restritas."""
        normalized_command = (command or "").strip().lower()
        payload = params if isinstance(params, dict) else {}

        if not normalized_command:
            return self._error("Comando invalido", "Nenhum comando informado.")

        command_map = {
            "get_status": self.get_status,
            "validate_file": lambda: self.validate_file(payload.get("file_path")),
            "scan_download": lambda: self.scan_download(payload.get("file_path")),
            "check_url": lambda: self.check_url(payload.get("url")),
            "ping": self.ping,
            "get_version": self.get_version,
        }

        handler = command_map.get(normalized_command)
        if handler is None:
            return self._error("Comando nao suportado", f"Comando recebido: {normalized_command}")

        try:
            self._log_integration(f"Comando recebido: {normalized_command}")
            response = handler()
            self._log_integration(
                f"Comando concluido: {normalized_command} | ok={response.get('ok', False)}"
            )
            return response
        except Exception as error:
            self._log_exception(f"Falha no comando {normalized_command}", error)
            return self._error("Falha ao executar comando", str(error))

    def ping(self) -> dict[str, Any]:
        """Resposta de saude para validar disponibilidade da API local."""
        if not self._ready:
            return self._error("Antivirus indisponivel", self._init_error or "Inicializacao incompleta")

        return self._success(
            "Antivirus conectado",
            {
                "status": "running",
                "api_available": True,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
            status="running",
        )

    def get_version(self) -> dict[str, Any]:
        """Retorna versoes do aplicativo e da API de integracao."""
        if not self._ready:
            return self._error("Falha ao obter versao", self._init_error or "Integracao nao inicializada")

        return self._success(
            "Versao obtida com sucesso",
            {
                "app_version": APP_VERSION,
                "api_version": self.API_VERSION,
            },
        )

    def get_status(self) -> dict[str, Any]:
        """Estado consolidado para o preload confirmar disponibilidade do backend."""
        if not self._ready:
            return self._error("Antivirus nao inicializado", self._init_error or "Erro desconhecido")

        assert self.paths is not None

        uptime_seconds = int((datetime.now(timezone.utc) - self._started_at).total_seconds())
        return self._success(
            "Status consultado com sucesso",
            {
                "status": "running",
                "api_available": True,
                "uptime_seconds": uptime_seconds,
                "runtime_base_dir": str(self.paths.base_dir),
                "logs_dir": str(self.paths.logs_dir),
                "quarantine_dir": str(self.paths.quarantine_dir),
                "installation_path_valid": self._installation_path is None or self._installation_path.exists(),
            },
            status="running",
        )

    def validate_file(self, file_path: Any) -> dict[str, Any]:
        """Valida caminho e metadados principais de um arquivo recebido do navegador."""
        if not self._ready:
            return self._error("Falha ao analisar arquivo", self._init_error or "Integracao nao inicializada")

        parsed = self._parse_file_path(file_path)
        if not parsed["ok"]:
            return parsed

        target = Path(parsed["data"]["file_path"])
        exists = target.exists()
        is_file = target.is_file()
        extension = target.suffix.lower()
        path_valid = self._is_valid_local_path(target)

        suspicious_extension = extension in self.SUSPICIOUS_FILE_EXTENSIONS
        double_extension = self._has_suspicious_double_extension(target.name)

        file_hash = ""
        file_size = 0
        heuristic_score = 0
        heuristic_reasons: list[str] = []
        suspicious = suspicious_extension or double_extension

        if exists and is_file:
            file_hash = self._sha256_of(target)
            file_size = target.stat().st_size
            heuristic_score, heuristic_reasons, suspicious = self._evaluate_file_risk(target, suspicious)

        return self._success(
            "Arquivo analisado com sucesso",
            {
                "file_path": str(target),
                "exists": exists,
                "path_valid": path_valid,
                "is_file": is_file,
                "extension": extension or "sem_extensao",
                "suspicious_extension": suspicious_extension,
                "double_extension": double_extension,
                "hash": file_hash,
                "size": file_size,
                "heuristic_score": heuristic_score,
                "heuristic_reasons": heuristic_reasons,
                "suspicious": suspicious,
            },
        )

    def scan_download(self, file_path: Any) -> dict[str, Any]:
        """Executa analise de download com sinais adicionais de risco para browser."""
        if not self._ready:
            return self._error("Falha ao analisar arquivo", self._init_error or "Integracao nao inicializada")

        validation_result = self.validate_file(file_path)
        if not validation_result.get("ok"):
            return validation_result

        data = dict(validation_result.get("data") or {})
        if not data.get("exists") or not data.get("is_file"):
            return self._error("Falha ao analisar arquivo", "Arquivo de download nao encontrado ou invalido")

        target = Path(str(data["file_path"]))
        normalized = str(target).lower().replace("/", "\\")

        in_downloads_directory = "\\downloads\\" in normalized
        recently_modified_seconds = max(0, int(datetime.now().timestamp() - target.stat().st_mtime))
        recently_modified_hours = round(recently_modified_seconds / 3600, 2)

        suspicious_reasons = list(data.get("heuristic_reasons") or [])
        score = int(data.get("heuristic_score") or 0)

        if data.get("suspicious_extension"):
            score += 25
            suspicious_reasons.append("Arquivo de download com extensao potencialmente perigosa")

        if data.get("double_extension"):
            score += 30
            suspicious_reasons.append("Nome com dupla extensao enganosa")

        if in_downloads_directory and recently_modified_hours <= 72:
            score += 10
            suspicious_reasons.append("Download recente em pasta de alto risco")

        suspicious = score >= 20 or bool(data.get("suspicious"))

        response_data = {
            "file_path": str(target),
            "exists": True,
            "hash": data.get("hash", ""),
            "size": data.get("size", 0),
            "path_valid": data.get("path_valid", False),
            "in_downloads_directory": in_downloads_directory,
            "recently_modified_hours": recently_modified_hours,
            "suspicious": suspicious,
            "risk_score": min(score, 100),
            "risk_reasons": list(dict.fromkeys(suspicious_reasons)),
        }
        return self._success("Arquivo analisado com sucesso", response_data)

    def check_url(self, url: Any) -> dict[str, Any]:
        """Verifica URL suspeita para navegacao segura no navegador integrado."""
        if not self._ready:
            return self._error("Falha ao analisar URL", self._init_error or "Integracao nao inicializada")

        if not isinstance(url, str) or not url.strip():
            return self._error("Falha ao analisar URL", "URL invalida ou ausente")

        target_url = url.strip()
        if not (target_url.startswith("http://") or target_url.startswith("https://")):
            return self._error("Falha ao analisar URL", "URL deve iniciar com http:// ou https://")

        assert self.url_threat_service is not None
        assessment = self.url_threat_service.assess_url(target_url)

        return self._success(
            "URL analisada com sucesso",
            {
                "url": target_url,
                "suspicious": assessment.suspicious,
                "score": assessment.score,
                "reasons": assessment.reasons,
            },
        )

    def _parse_file_path(self, file_path: Any) -> dict[str, Any]:
        if not isinstance(file_path, str) or not file_path.strip():
            return self._error("Falha ao analisar arquivo", "Parametro file_path invalido")

        try:
            target = Path(file_path).expanduser().resolve()
        except Exception as error:
            return self._error("Falha ao analisar arquivo", f"Caminho invalido: {error}")

        return self._success("Caminho validado com sucesso", {"file_path": str(target)})

    def _evaluate_file_risk(self, target: Path, current_suspicious: bool) -> tuple[int, list[str], bool]:
        assert self.heuristic_engine is not None

        extension = target.suffix.lower()
        normalized_path = str(target).lower().replace("/", "\\")

        is_sensitive_extension = extension in self.SUSPICIOUS_FILE_EXTENSIONS
        is_temporary_location = any(
            marker in normalized_path for marker in FileScannerService.TEMPORARY_DIRECTORY_MARKERS
        )
        is_unusual_location = any(
            marker in normalized_path for marker in FileScannerService.UNUSUAL_DIRECTORY_MARKERS
        )

        evaluation = self.heuristic_engine.evaluate_file(
            path=target,
            extension=extension,
            is_sensitive_extension=is_sensitive_extension,
            is_temporary_location=is_temporary_location,
            is_unusual_location=is_unusual_location,
            signature_publisher=None,
        )
        suspicious = current_suspicious or evaluation.classification != ThreatClassification.TRUSTED
        return evaluation.score, evaluation.reasons, suspicious

    def _is_valid_local_path(self, path: Path) -> bool:
        raw = str(path)
        if raw.startswith("\\\\"):
            return False
        if path.drive == "":
            return False
        return True

    def _has_suspicious_double_extension(self, file_name: str) -> bool:
        lowered_name = file_name.lower()
        parts = lowered_name.split(".")
        if len(parts) < 3:
            return False

        first_ext = f".{parts[-2]}"
        last_ext = f".{parts[-1]}"
        return first_ext in self.DOUBLE_EXTENSION_SUFFIXES and last_ext in self.SUSPICIOUS_FILE_EXTENSIONS

    def _sha256_of(self, path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as file_handle:
            for chunk in iter(lambda: file_handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    def _success(self, message: str, data: dict[str, Any] | None = None, *, status: str = "ok") -> dict[str, Any]:
        response: dict[str, Any] = {
            "ok": True,
            "status": status,
            "message": message,
        }
        if data is not None:
            response["data"] = data
        return response

    def _error(self, message: str, error: str, *, status: str = "error") -> dict[str, Any]:
        return {
            "ok": False,
            "status": status,
            "message": message,
            "error": error,
        }

    def _log_integration(self, message: str) -> None:
        if self.logger is not None:
            log_info(self.logger, f"[Bridge] {message}")
        elif self._integration_logger is not None:
            self._integration_logger.info(message)

    def _log_exception(self, message: str, error: Exception) -> None:
        if self.logger is not None:
            log_error(self.logger, f"[Bridge] {message}", error)
        elif self._integration_logger is not None:
            self._integration_logger.exception(message)
        else:
            log_warning(logging.getLogger("sentinelapc.bridge"), f"{message}: {error}")


_singleton_bridge: AntivirusBridge | None = None
_singleton_lock = threading.Lock()


def get_bridge(installation_path: str | Path | None = None) -> AntivirusBridge:
    """Retorna instancia singleton para uso em API local e chamadas repetidas."""
    global _singleton_bridge

    with _singleton_lock:
        if _singleton_bridge is None:
            _singleton_bridge = AntivirusBridge(installation_path=installation_path)
        return _singleton_bridge
