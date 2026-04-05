"""Analise estatica de arquivos para detectar mascaramento, ofuscacao e payloads ocultos."""

from __future__ import annotations

from math import log2
from pathlib import Path
import re

from app.services.risk_engine import RiskSignal


class StaticFileAnalyzer:
    """Inspeciona sinais estaticos sem executar o arquivo."""

    DOUBLE_EXTENSION_PATTERN = re.compile(
        r"\.(pdf|jpg|jpeg|png|gif|txt|doc|docx|xls|xlsx|ppt|pptx)\.(exe|scr|bat|cmd|js|vbs|ps1)$",
        re.IGNORECASE,
    )
    BASE64_CHUNK_PATTERN = re.compile(r"[A-Za-z0-9+/]{160,}={0,2}")
    SUSPICIOUS_NAME_PATTERN = re.compile(
        r"(invoice|receipt|update|security|patch|urgent|payment|bank|download|crack|keygen)",
        re.IGNORECASE,
    )

    EXECUTABLE_EXTENSIONS = {".exe", ".dll", ".scr", ".com", ".jar"}
    SCRIPT_EXTENSIONS = {".ps1", ".vbs", ".js", ".bat", ".cmd", ".hta"}

    MAGIC_BY_EXTENSION: dict[str, bytes] = {
        ".exe": b"MZ",
        ".dll": b"MZ",
        ".scr": b"MZ",
        ".pdf": b"%PDF",
        ".png": b"\x89PNG",
        ".zip": b"PK\x03\x04",
    }

    def analyze_file(self, *, file_path: Path, extension: str, file_size: int, head: bytes) -> list[RiskSignal]:
        """Retorna sinais estaticos ponderados para o arquivo analisado."""
        signals: list[RiskSignal] = []

        filename = file_path.name
        normalized_name = filename.lower()
        normalized_path = str(file_path).lower().replace("/", "\\")

        if self.DOUBLE_EXTENSION_PATTERN.search(normalized_name):
            signals.append(
                RiskSignal(
                    reason="Arquivo com dupla extensao usada para mascarar payload",
                    weight=26,
                    category="masquerading",
                    module="analyzer_static",
                )
            )

        if self.SUSPICIOUS_NAME_PATTERN.search(normalized_name):
            signals.append(
                RiskSignal(
                    reason="Nome com padrao recorrente em campanhas de malware",
                    weight=10,
                    category="phishing/payload",
                    module="analyzer_static",
                )
            )

        if filename.startswith("."):
            signals.append(
                RiskSignal(
                    reason="Arquivo oculto com extensao sensivel",
                    weight=8,
                    category="evasao",
                    module="analyzer_static",
                )
            )

        if extension in self.EXECUTABLE_EXTENSIONS and file_size < 12 * 1024:
            signals.append(
                RiskSignal(
                    reason="Executavel muito pequeno para binario legitimo comum",
                    weight=14,
                    category="trojan/dropper",
                    module="analyzer_static",
                )
            )

        if extension in self.SCRIPT_EXTENSIONS and file_size > 5 * 1024 * 1024:
            signals.append(
                RiskSignal(
                    reason="Script com tamanho anormalmente alto",
                    weight=12,
                    category="script_suspeito",
                    module="analyzer_static",
                )
            )

        magic_signal = self._check_magic_mismatch(extension, head)
        if magic_signal is not None:
            signals.append(magic_signal)

        text_sample = head.decode("utf-8", errors="ignore").lower()
        obfuscation_signals = self._detect_obfuscation(text_sample)
        signals.extend(obfuscation_signals)

        entropy = self._calculate_entropy(head)
        if entropy >= 7.2 and extension in self.SCRIPT_EXTENSIONS | self.EXECUTABLE_EXTENSIONS:
            signals.append(
                RiskSignal(
                    reason=f"Entropia elevada no cabecalho ({entropy:.2f}) indica possivel ofuscacao/packing",
                    weight=18,
                    category="ofuscacao",
                    module="analyzer_static",
                )
            )

        if "\\windows\\tasks\\" in normalized_path or "\\startup\\" in normalized_path:
            signals.append(
                RiskSignal(
                    reason="Arquivo sensivel localizado em area de persistencia",
                    weight=18,
                    category="persistencia",
                    module="analyzer_static",
                )
            )

        return signals

    def _check_magic_mismatch(self, extension: str, head: bytes) -> RiskSignal | None:
        expected_magic = self.MAGIC_BY_EXTENSION.get(extension)
        if expected_magic is not None and not head.startswith(expected_magic):
            return RiskSignal(
                reason="Extensao declarada nao combina com assinatura binaria (magic bytes)",
                weight=24,
                category="masquerading",
                module="analyzer_static",
            )

        if extension not in self.EXECUTABLE_EXTENSIONS and head.startswith(b"MZ"):
            return RiskSignal(
                reason="Cabecalho executavel detectado em arquivo com extensao nao executavel",
                weight=35,
                category="payload_oculto",
                module="analyzer_static",
            )

        return None

    def _detect_obfuscation(self, sample: str) -> list[RiskSignal]:
        signals: list[RiskSignal] = []

        markers = {
            "frombase64string": 16,
            "-encodedcommand": 20,
            "eval(function(p,a,c,k,e,d)": 20,
            "string.fromcharcode": 16,
            "wscript.shell": 14,
            "invoke-expression": 16,
            "new-object net.webclient": 18,
            "downloadstring(": 18,
            "mshta": 18,
            "regsvr32 /s": 16,
        }
        matched = [marker for marker in markers if marker in sample]
        for marker in matched:
            signals.append(
                RiskSignal(
                    reason=f"Marcador de ofuscacao/execucao suspeita detectado: {marker}",
                    weight=markers[marker],
                    category="script_suspeito",
                    module="analyzer_static",
                )
            )

        if self.BASE64_CHUNK_PATTERN.search(sample):
            signals.append(
                RiskSignal(
                    reason="Trecho longo em base64 detectado (possivel payload embutido)",
                    weight=14,
                    category="ofuscacao",
                    module="analyzer_static",
                )
            )

        return signals

    def _calculate_entropy(self, content: bytes) -> float:
        if not content:
            return 0.0

        histogram: dict[int, int] = {}
        for byte in content:
            histogram[byte] = histogram.get(byte, 0) + 1

        total = len(content)
        entropy = 0.0
        for count in histogram.values():
            probability = count / total
            entropy -= probability * log2(probability)
        return entropy
