"""Analise de contexto para reduzir falsos positivos e ponderar legitimidade."""

from __future__ import annotations

from pathlib import Path

from app.services.risk_engine import RiskSignal


class ContextAnalyzer:
    """Aplica sinais de confianca ou risco com base em localizacao e coerencia."""

    TRUSTED_PUBLISHERS = (
        "microsoft",
        "google",
        "mozilla",
        "opera",
        "apple",
        "python software foundation",
    )

    BROWSER_EXTENSION_MARKERS = (
        "\\chrome\\user data\\",
        "\\edge\\user data\\",
        "\\opera software\\",
        "\\mozilla\\firefox\\profiles\\",
    )

    EXPECTED_EXTENSION_FILES = {
        "manifest.json",
        "background.js",
        "service_worker.js",
        "content.js",
        "content_script.js",
    }

    def analyze_file_context(
        self,
        *,
        file_path: Path,
        extension: str,
        signature_publisher: str | None,
    ) -> list[RiskSignal]:
        """Retorna sinais de ajuste contextual (positivos e negativos)."""
        signals: list[RiskSignal] = []
        normalized_path = str(file_path).lower().replace("/", "\\")
        filename = file_path.name.lower()

        if self._is_program_files_path(normalized_path) and self._publisher_is_trusted(signature_publisher):
            signals.append(
                RiskSignal(
                    reason="Arquivo assinado por editora confiavel em Program Files",
                    weight=-24,
                    category="contexto_legitimo",
                    module="analyzer_context",
                )
            )

        if "\\windows\\system32\\" in normalized_path and self._publisher_is_trusted(signature_publisher):
            signals.append(
                RiskSignal(
                    reason="Arquivo de sistema em caminho oficial com assinatura valida",
                    weight=-28,
                    category="contexto_legitimo",
                    module="analyzer_context",
                )
            )

        if any(marker in normalized_path for marker in self.BROWSER_EXTENSION_MARKERS):
            if extension in {".json", ".js", ".css", ".html", ".png", ".svg", ".map", ".wasm"}:
                signals.append(
                    RiskSignal(
                        reason="Arquivo em estrutura de extensao de navegador compativel com componente esperado",
                        weight=-12,
                        category="contexto_browser",
                        module="analyzer_context",
                    )
                )

            if filename in self.EXPECTED_EXTENSION_FILES:
                signals.append(
                    RiskSignal(
                        reason="Nome de arquivo comum em extensoes legitimas",
                        weight=-8,
                        category="contexto_browser",
                        module="analyzer_context",
                    )
                )

        if extension in {".exe", ".dll", ".scr"} and ("\\downloads\\" in normalized_path or "\\desktop\\" in normalized_path):
            signals.append(
                RiskSignal(
                    reason="Executavel em area tipica de entrega de payload (Downloads/Desktop)",
                    weight=10,
                    category="contexto_risco",
                    module="analyzer_context",
                )
            )

        return signals

    def _is_program_files_path(self, normalized_path: str) -> bool:
        return "\\program files\\" in normalized_path or "\\program files (x86)\\" in normalized_path

    def _publisher_is_trusted(self, signature_publisher: str | None) -> bool:
        if not signature_publisher:
            return False
        publisher = signature_publisher.lower()
        return any(item in publisher for item in self.TRUSTED_PUBLISHERS)
