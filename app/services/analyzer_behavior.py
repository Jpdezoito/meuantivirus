"""Analise comportamental de processos para sinais de ransomware, trojan e fileless."""

from __future__ import annotations

from pathlib import Path

from app.services.risk_engine import RiskSignal


class ProcessBehaviorAnalyzer:
    """Gera sinais comportamentais a partir de metadados e telemetria do processo."""

    FILELESS_HOSTS = {"powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe"}
    OFFICE_PARENTS = {"winword.exe", "excel.exe", "outlook.exe", "powerpnt.exe"}

    def analyze_process(
        self,
        *,
        process_name: str,
        executable_path: Path | None,
        cpu_samples: list[float],
        memory_samples: list[float],
        command_line: str,
        parent_name: str,
    ) -> list[RiskSignal]:
        """Retorna sinais ponderados de comportamento suspeito."""
        signals: list[RiskSignal] = []

        name = process_name.lower()
        normalized_path = str(executable_path).lower().replace("/", "\\") if executable_path else ""
        command = command_line.lower()
        parent = parent_name.lower()

        if name in self.FILELESS_HOSTS and any(
            marker in command
            for marker in ("-encodedcommand", "invoke-expression", "frombase64string", "downloadstring", "hidden")
        ):
            signals.append(
                RiskSignal(
                    reason="Padrao de execucao fileless com shell/scripting host",
                    weight=34,
                    category="fileless",
                    module="analyzer_behavior",
                )
            )

        if parent in self.OFFICE_PARENTS and name in self.FILELESS_HOSTS:
            signals.append(
                RiskSignal(
                    reason="Processo Office disparando shell/script host (cadeia suspeita)",
                    weight=28,
                    category="trojan/phishing",
                    module="analyzer_behavior",
                )
            )

        if "\\appdata\\local\\temp\\" in normalized_path or "\\temp\\" in normalized_path:
            signals.append(
                RiskSignal(
                    reason="Processo executando a partir de diretorio temporario",
                    weight=24,
                    category="trojan/dropper",
                    module="analyzer_behavior",
                )
            )

        if any(marker in command for marker in ("vssadmin delete shadows", "wbadmin delete", "bcdedit /set", "cipher /w")):
            signals.append(
                RiskSignal(
                    reason="Comando compatível com comportamento de ransomware/wiper",
                    weight=46,
                    category="ransomware/wiper",
                    module="analyzer_behavior",
                )
            )

        if self._sustained_high_cpu(cpu_samples):
            signals.append(
                RiskSignal(
                    reason="CPU elevada sustentada sugere possivel cryptojacking",
                    weight=18,
                    category="cryptojacker",
                    module="analyzer_behavior",
                )
            )

        if self._sustained_high_memory(memory_samples):
            signals.append(
                RiskSignal(
                    reason="Memoria elevada sustentada durante amostragem",
                    weight=8,
                    category="comportamento_anomalo",
                    module="analyzer_behavior",
                )
            )

        return signals

    def _sustained_high_cpu(self, samples: list[float]) -> bool:
        if len(samples) < 3:
            return False
        high = sum(sample >= 70.0 for sample in samples)
        average = sum(samples) / len(samples)
        return high >= 2 and average >= 60.0

    def _sustained_high_memory(self, samples: list[float]) -> bool:
        if len(samples) < 3:
            return False
        high = sum(sample >= 25.0 for sample in samples)
        average = sum(samples) / len(samples)
        return high >= 2 and average >= 20.0
