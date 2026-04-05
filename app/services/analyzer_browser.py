"""Analise de extensoes e scripts de navegador com foco em sinais reais e contexto."""

from __future__ import annotations

import json
from pathlib import Path
import re

from app.services.risk_engine import RiskSignal


class BrowserExtensionAnalyzer:
    """Avalia manifestos e scripts JS de extensoes sem assumir que todo JS e malicioso."""

    DANGEROUS_PERMISSIONS = {
        "proxy",
        "management",
        "webRequest",
        "webRequestBlocking",
        "downloads",
        "history",
        "tabs",
        "nativeMessaging",
    }

    JS_SUSPICIOUS_MARKERS = {
        "eval(": 12,
        "new function(": 12,
        "atob(": 8,
        "fromcharcode": 10,
        "webrequestblocking": 8,
        "chrome.proxy": 10,
        "document.cookie": 8,
        "fetch(\"http": 10,
        "xmlhttprequest": 8,
    }

    LONG_BASE64_PATTERN = re.compile(r"[A-Za-z0-9+/]{180,}={0,2}")

    def analyze_manifest(self, manifest_path: Path, manifest_data: dict) -> list[RiskSignal]:
        """Gera sinais de risco de acordo com permissoes e metadados do manifesto."""
        signals: list[RiskSignal] = []

        name = str(manifest_data.get("name") or "").strip()
        permissions = [str(item) for item in (manifest_data.get("permissions") or [])]
        host_permissions = [str(item) for item in (manifest_data.get("host_permissions") or [])]
        update_url = str(manifest_data.get("update_url") or "")

        dangerous = [perm for perm in permissions if perm in self.DANGEROUS_PERMISSIONS]
        if len(dangerous) >= 3:
            signals.append(
                RiskSignal(
                    reason="Extensao com combinacao ampla de permissoes sensiveis",
                    weight=24,
                    category="malvertising/spyware",
                    module="analyzer_browser",
                )
            )
        elif dangerous:
            signals.append(
                RiskSignal(
                    reason="Extensao com permissao sensivel relevante",
                    weight=10,
                    category="browser_risco",
                    module="analyzer_browser",
                )
            )

        if any("<all_urls>" in item for item in host_permissions):
            signals.append(
                RiskSignal(
                    reason="Permissao de acesso a todos os domínios (<all_urls>)",
                    weight=14,
                    category="spyware",
                    module="analyzer_browser",
                )
            )

        if len(name) <= 2 or name.lower() in {"extension", "default", "unknown"}:
            signals.append(
                RiskSignal(
                    reason="Manifesto com nome pouco descritivo",
                    weight=8,
                    category="contexto_suspeito",
                    module="analyzer_browser",
                )
            )

        if update_url and ("google.com" in update_url or "microsoft.com" in update_url):
            signals.append(
                RiskSignal(
                    reason="Canal de atualizacao oficial detectado para a extensao",
                    weight=-12,
                    category="contexto_legitimo",
                    module="analyzer_browser",
                )
            )

        if manifest_path.parent.name.count(".") >= 2:
            signals.append(
                RiskSignal(
                    reason="Estrutura de versao da extensao parece coerente",
                    weight=-6,
                    category="contexto_legitimo",
                    module="analyzer_browser",
                )
            )

        return signals

    def analyze_extension_scripts(self, extension_root: Path, *, max_files: int = 6) -> list[RiskSignal]:
        """Inspeciona alguns scripts JS para detectar ofuscacao e comportamentos abusivos."""
        signals: list[RiskSignal] = []
        inspected = 0

        for script_file in extension_root.rglob("*.js"):
            if inspected >= max_files:
                break
            inspected += 1

            try:
                content = script_file.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue

            lowered = content.lower()

            matched_markers = [marker for marker in self.JS_SUSPICIOUS_MARKERS if marker in lowered]
            for marker in matched_markers:
                signals.append(
                    RiskSignal(
                        reason=f"Script de extensao com marcador sensivel: {marker}",
                        weight=self.JS_SUSPICIOUS_MARKERS[marker],
                        category="script_js_suspeito",
                        module="analyzer_browser",
                    )
                )

            if self.LONG_BASE64_PATTERN.search(lowered):
                signals.append(
                    RiskSignal(
                        reason="Script JS contem bloco longo em base64 (possivel ofuscacao)",
                        weight=12,
                        category="ofuscacao",
                        module="analyzer_browser",
                    )
                )

            if len(content) > 900_000 and "sourceMappingURL" not in content:
                signals.append(
                    RiskSignal(
                        reason="Script JS grande sem indicio de build/source map",
                        weight=8,
                        category="anomalia_script",
                        module="analyzer_browser",
                    )
                )

            # Evita excesso de sinais repetidos do mesmo arquivo.
            if len(signals) >= 12:
                break

        return signals

    def load_manifest(self, manifest_path: Path) -> dict | None:
        """Carrega manifesto de extensao com tratamento defensivo."""
        try:
            return json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
