"""Servico de analise local de seguranca para navegadores no Windows."""

from __future__ import annotations

from collections.abc import Callable
import json
import logging
import os
from pathlib import Path
import re
import subprocess
import time

from app.core.heuristics import HeuristicEngine
from app.core.risk import ThreatClassification
from app.services.browser_scan_models import BrowserScanError, BrowserScanItem, BrowserScanReport
from app.services.file_scanner_service import ScanControl
from app.utils.logger import log_info, log_warning


class BrowserSecurityService:
    """Analisa executaveis, extensoes, sinais de hijack e downloads suspeitos."""

    DANGEROUS_EXTENSIONS = {".exe", ".bat", ".cmd", ".scr", ".ps1", ".vbs", ".js"}
    EXCESSIVE_PERMISSIONS = {
        "proxy",
        "management",
        "webRequest",
        "webRequestBlocking",
        "downloads",
        "history",
        "tabs",
        "notifications",
    }

    def __init__(self, logger: logging.Logger, heuristic_engine: HeuristicEngine) -> None:
        self.logger = logger
        self.heuristic_engine = heuristic_engine

    def analyze_browsers(
        self,
        progress_callback: Callable[[str], None] | None = None,
        scan_control: ScanControl | None = None,
    ) -> BrowserScanReport:
        """Executa analise local e defensiva de navegadores sem acessar dados sensiveis."""
        self._emit_progress(progress_callback, "[Navegadores] Iniciando analise local de navegadores...")

        results: list[BrowserScanItem] = []
        errors: list[BrowserScanError] = []
        inspected_items = 0

        for browser_name, executable in self._discover_browser_executables().items():
            if not self._await_scan_control(scan_control, progress_callback):
                break

            inspected_items += 1
            item = self._analyze_browser_executable(browser_name, executable)
            if item is not None:
                results.append(item)

            ext_results, ext_inspected, ext_errors = self._analyze_browser_extensions(browser_name, scan_control, progress_callback)
            inspected_items += ext_inspected
            results.extend(ext_results)
            errors.extend(ext_errors)

            hijack_results, hijack_inspected, hijack_errors = self._analyze_hijack_signals(browser_name)
            inspected_items += hijack_inspected
            results.extend(hijack_results)
            errors.extend(hijack_errors)

        download_results, download_inspected, download_errors = self._analyze_recent_downloads(scan_control, progress_callback)
        inspected_items += download_inspected
        results.extend(download_results)
        errors.extend(download_errors)

        suspicious_items = sum(item.classification != ThreatClassification.TRUSTED for item in results)
        report = BrowserScanReport(
            inspected_items=inspected_items,
            suspicious_items=suspicious_items,
            interrupted=scan_control.is_cancelled() if scan_control is not None else False,
            results=results,
            errors=errors,
        )
        log_info(
            self.logger,
            (
                "Analise de navegadores concluida | "
                f"itens={report.inspected_items} | suspeitos={report.suspicious_items} | erros={len(report.errors)}"
            ),
        )
        self._emit_progress(
            progress_callback,
            (
                "[Navegadores] Analise concluida. "
                f"Itens avaliados: {report.inspected_items}. "
                f"Suspeitos: {report.suspicious_items}."
            ),
        )
        return report

    def _discover_browser_executables(self) -> dict[str, Path]:
        program_files = os.environ.get("ProgramFiles", r"C:\Program Files")
        program_files_x86 = os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")

        candidates = {
            "Chrome": [
                Path(program_files) / "Google" / "Chrome" / "Application" / "chrome.exe",
                Path(program_files_x86) / "Google" / "Chrome" / "Application" / "chrome.exe",
            ],
            "Edge": [
                Path(program_files) / "Microsoft" / "Edge" / "Application" / "msedge.exe",
                Path(program_files_x86) / "Microsoft" / "Edge" / "Application" / "msedge.exe",
            ],
            "Firefox": [
                Path(program_files) / "Mozilla Firefox" / "firefox.exe",
                Path(program_files_x86) / "Mozilla Firefox" / "firefox.exe",
            ],
            "Opera": [
                Path(program_files) / "Opera" / "launcher.exe",
                Path(program_files_x86) / "Opera" / "launcher.exe",
                Path.home() / "AppData" / "Local" / "Programs" / "Opera" / "launcher.exe",
            ],
        }

        installed: dict[str, Path] = {}
        for browser_name, browser_paths in candidates.items():
            for candidate in browser_paths:
                if candidate.exists() and candidate.is_file():
                    installed[browser_name] = candidate
                    break
        return installed

    def _analyze_browser_executable(self, browser: str, executable: Path) -> BrowserScanItem | None:
        normalized = str(executable).lower().replace("/", "\\")
        score = 0
        reasons: list[str] = []

        if "\\program files\\" in normalized or "\\program files (x86)\\" in normalized:
            score -= 20
            reasons.append("Executavel em caminho legitimo de instalacao")
        if "\\temp\\" in normalized or "\\appdata\\local\\temp\\" in normalized:
            score += 40
            reasons.append("Executavel do navegador em pasta temporaria")

        if executable.name.lower() not in {"chrome.exe", "msedge.exe", "firefox.exe", "launcher.exe"}:
            score += 20
            reasons.append("Nome de executavel inesperado para navegador conhecido")

        evaluation = self.heuristic_engine.build_custom_evaluation(max(0, score), reasons)
        if evaluation.classification == ThreatClassification.TRUSTED:
            return None

        return BrowserScanItem(
            browser=browser,
            item_type="Executavel",
            name=executable.name,
            path=executable,
            score=evaluation.score,
            risk_level=evaluation.risk_level,
            classification=evaluation.classification,
            reasons=list(evaluation.reasons),
        )

    def _analyze_browser_extensions(
        self,
        browser: str,
        scan_control: ScanControl | None,
        progress_callback: Callable[[str], None] | None,
    ) -> tuple[list[BrowserScanItem], int, list[BrowserScanError]]:
        results: list[BrowserScanItem] = []
        errors: list[BrowserScanError] = []
        inspected = 0

        extension_dirs = self._extension_roots(browser)
        for extension_root in extension_dirs:
            if not extension_root.exists():
                continue

            for manifest_path in extension_root.rglob("manifest.json"):
                if not self._await_scan_control(scan_control, progress_callback):
                    return results, inspected, errors

                inspected += 1
                item = self._analyze_extension_manifest(browser, manifest_path)
                if item is not None:
                    results.append(item)

        return results, inspected, errors

    def _extension_roots(self, browser: str) -> list[Path]:
        local_appdata = Path(os.environ.get("LOCALAPPDATA", str(Path.home() / "AppData" / "Local")))
        roaming = Path(os.environ.get("APPDATA", str(Path.home() / "AppData" / "Roaming")))

        if browser == "Chrome":
            return [local_appdata / "Google" / "Chrome" / "User Data" / "Default" / "Extensions"]
        if browser == "Edge":
            return [local_appdata / "Microsoft" / "Edge" / "User Data" / "Default" / "Extensions"]
        if browser == "Opera":
            return [roaming / "Opera Software" / "Opera Stable" / "Extensions"]
        if browser == "Firefox":
            return [roaming / "Mozilla" / "Firefox" / "Profiles"]
        return []

    def _analyze_extension_manifest(self, browser: str, manifest_path: Path) -> BrowserScanItem | None:
        try:
            data = json.loads(manifest_path.read_text(encoding="utf-8"))
        except Exception as error:
            log_warning(self.logger, f"Falha ao ler manifest da extensao: {manifest_path} | {error}")
            return None

        name = str(data.get("name") or "sem_nome").strip()
        permissions = data.get("permissions") or []
        host_permissions = data.get("host_permissions") or []

        score = 0
        reasons: list[str] = []

        if name.lower() in {"extension", "new tab", "unknown", "sem_nome"} or len(name) <= 2:
            score += 15
            reasons.append("Extensao sem identificacao clara")

        excessive = [perm for perm in permissions if str(perm) in self.EXCESSIVE_PERMISSIONS]
        if len(excessive) >= 3:
            score += 25
            reasons.append("Permissoes excessivas para extensao")
        elif excessive:
            score += 12
            reasons.append("Permissoes elevadas presentes")

        if any("<all_urls>" in str(item) for item in host_permissions):
            score += 15
            reasons.append("Acesso amplo a todos os sites")

        evaluation = self.heuristic_engine.build_custom_evaluation(score, reasons)
        if evaluation.classification == ThreatClassification.TRUSTED:
            return None

        return BrowserScanItem(
            browser=browser,
            item_type="Extensao",
            name=name,
            path=manifest_path.parent,
            score=evaluation.score,
            risk_level=evaluation.risk_level,
            classification=evaluation.classification,
            reasons=list(evaluation.reasons),
        )

    def _analyze_hijack_signals(self, browser: str) -> tuple[list[BrowserScanItem], int, list[BrowserScanError]]:
        results: list[BrowserScanItem] = []
        errors: list[BrowserScanError] = []
        inspected = 0

        preferences_path = self._preferences_path(browser)
        if preferences_path is not None and preferences_path.exists():
            inspected += 1
            item = self._analyze_preferences(browser, preferences_path)
            if item is not None:
                results.append(item)

        proxy_item, proxy_checked = self._analyze_proxy_configuration(browser)
        inspected += proxy_checked
        if proxy_item is not None:
            results.append(proxy_item)

        shortcut_item, shortcut_checked = self._analyze_shortcuts(browser)
        inspected += shortcut_checked
        if shortcut_item is not None:
            results.append(shortcut_item)

        return results, inspected, errors

    def _preferences_path(self, browser: str) -> Path | None:
        local_appdata = Path(os.environ.get("LOCALAPPDATA", str(Path.home() / "AppData" / "Local")))
        roaming = Path(os.environ.get("APPDATA", str(Path.home() / "AppData" / "Roaming")))
        if browser == "Chrome":
            return local_appdata / "Google" / "Chrome" / "User Data" / "Default" / "Preferences"
        if browser == "Edge":
            return local_appdata / "Microsoft" / "Edge" / "User Data" / "Default" / "Preferences"
        if browser == "Opera":
            return roaming / "Opera Software" / "Opera Stable" / "Preferences"
        return None

    def _analyze_preferences(self, browser: str, preferences_path: Path) -> BrowserScanItem | None:
        try:
            data = json.loads(preferences_path.read_text(encoding="utf-8"))
        except Exception:
            return None

        score = 0
        reasons: list[str] = []

        homepage = str(data.get("homepage") or "")
        if homepage and self._is_suspicious_url(homepage):
            score += 30
            reasons.append("Homepage aponta para dominio suspeito")

        default_search = data.get("default_search_provider") or {}
        search_url = str(default_search.get("search_url") or "")
        if search_url and self._is_suspicious_url(search_url):
            score += 30
            reasons.append("Mecanismo de busca padrao aponta para dominio suspeito")

        evaluation = self.heuristic_engine.build_custom_evaluation(score, reasons)
        if evaluation.classification == ThreatClassification.TRUSTED:
            return None

        return BrowserScanItem(
            browser=browser,
            item_type="Possivel hijack",
            name="Configuracoes de navegacao",
            path=preferences_path,
            score=evaluation.score,
            risk_level=evaluation.risk_level,
            classification=evaluation.classification,
            reasons=list(evaluation.reasons),
        )

    def _analyze_proxy_configuration(self, browser: str) -> tuple[BrowserScanItem | None, int]:
        try:
            completed = subprocess.run(
                [
                    "powershell",
                    "-NoProfile",
                    "-Command",
                    "(Get-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings').ProxyServer",
                ],
                capture_output=True,
                text=True,
                timeout=2,
                check=False,
            )
        except Exception:
            return None, 0

        proxy_server = completed.stdout.strip()
        if not proxy_server:
            return None, 1

        score = 0
        reasons: list[str] = []
        if "127.0.0.1" not in proxy_server and "localhost" not in proxy_server:
            score += 20
            reasons.append("Proxy incomum configurado no sistema")

        evaluation = self.heuristic_engine.build_custom_evaluation(score, reasons)
        if evaluation.classification == ThreatClassification.TRUSTED:
            return None, 1

        return (
            BrowserScanItem(
                browser=browser,
                item_type="Proxy",
                name="Configuracao de proxy",
                path=None,
                score=evaluation.score,
                risk_level=evaluation.risk_level,
                classification=evaluation.classification,
                reasons=list(evaluation.reasons),
            ),
            1,
        )

    def _analyze_shortcuts(self, browser: str) -> tuple[BrowserScanItem | None, int]:
        desktop = Path.home() / "Desktop"
        if not desktop.exists():
            return None, 0

        inspected = 0
        suspicious_count = 0
        for lnk in desktop.glob("*.lnk"):
            if browser.lower() not in lnk.name.lower():
                continue
            inspected += 1
            args = self._read_shortcut_arguments(lnk)
            if args and re.search(r"https?://", args, re.IGNORECASE):
                suspicious_count += 1

        if suspicious_count == 0:
            return None, inspected

        evaluation = self.heuristic_engine.build_custom_evaluation(
            min(60, suspicious_count * 25),
            ["Atalho de navegador com URL/argumentos incomuns"],
        )
        return (
            BrowserScanItem(
                browser=browser,
                item_type="Atalho",
                name="Atalhos do navegador",
                path=desktop,
                score=evaluation.score,
                risk_level=evaluation.risk_level,
                classification=evaluation.classification,
                reasons=list(evaluation.reasons),
            ),
            inspected,
        )

    def _read_shortcut_arguments(self, shortcut: Path) -> str:
        try:
            command = (
                "$w = New-Object -ComObject WScript.Shell; "
                f"$s = $w.CreateShortcut('{str(shortcut).replace("'", "''")}'); "
                "$s.Arguments"
            )
            completed = subprocess.run(
                ["powershell", "-NoProfile", "-Command", command],
                capture_output=True,
                text=True,
                timeout=2,
                check=False,
            )
            return completed.stdout.strip()
        except Exception:
            return ""

    def _analyze_recent_downloads(
        self,
        scan_control: ScanControl | None,
        progress_callback: Callable[[str], None] | None,
    ) -> tuple[list[BrowserScanItem], int, list[BrowserScanError]]:
        results: list[BrowserScanItem] = []
        errors: list[BrowserScanError] = []
        inspected = 0
        downloads = Path.home() / "Downloads"
        if not downloads.exists():
            return results, inspected, errors

        now = time.time()
        for file_path in downloads.iterdir():
            if not self._await_scan_control(scan_control, progress_callback):
                break
            if not file_path.is_file():
                continue
            inspected += 1

            age_hours = (now - file_path.stat().st_mtime) / 3600
            score = 0
            reasons: list[str] = []

            if file_path.suffix.lower() in self.DANGEROUS_EXTENSIONS:
                score += 25
                reasons.append("Arquivo de download com extensao potencialmente perigosa")

            if re.search(r"\.(pdf|doc|jpg|png)\.(exe|scr|bat|cmd)$", file_path.name, re.IGNORECASE):
                score += 35
                reasons.append("Nome de arquivo com dupla extensao enganosa")

            if age_hours <= 72 and score > 0:
                score += 10
                reasons.append("Arquivo perigoso baixado recentemente")

            evaluation = self.heuristic_engine.build_custom_evaluation(score, reasons)
            if evaluation.classification == ThreatClassification.TRUSTED:
                continue

            results.append(
                BrowserScanItem(
                    browser="Downloads",
                    item_type="Download",
                    name=file_path.name,
                    path=file_path,
                    score=evaluation.score,
                    risk_level=evaluation.risk_level,
                    classification=evaluation.classification,
                    reasons=list(evaluation.reasons),
                )
            )

        return results, inspected, errors

    def _is_suspicious_url(self, url: str) -> bool:
        lowered = url.lower()
        if any(service in lowered for service in ("bit.ly", "tinyurl", "t.co", "is.gd")):
            return True
        if re.search(r"[0-9][a-z]*[0-9]", lowered) and any(brand in lowered for brand in ("google", "microsoft", "paypal", "banco")):
            return True
        return False

    def _await_scan_control(
        self,
        scan_control: ScanControl | None,
        progress_callback: Callable[[str], None] | None,
    ) -> bool:
        if scan_control is None:
            return True

        while scan_control.is_paused():
            self._emit_progress(progress_callback, "[Navegadores] Analise pausada...")
            time.sleep(0.15)
            if scan_control.is_cancelled():
                return False

        return not scan_control.is_cancelled()

    def _emit_progress(self, progress_callback: Callable[[str], None] | None, message: str) -> None:
        if progress_callback is not None:
            progress_callback(message)
