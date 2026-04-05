"""Modelos para alertas e eventos do monitor de pre-execucao."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from app.core.risk import RiskLevel
from app.services.risk_engine import ResponseAction


@dataclass(frozen=True)
class PreExecutionAlert:
    """Alerta gerado para arquivo detectado em pasta monitorada antes da execucao."""

    file_path: Path
    score: int
    risk_level: RiskLevel
    recommended_action: ResponseAction
    reasons: list[str]
    categories: list[str]
    timestamp: datetime = field(default_factory=datetime.now)
    analysis_modules: list[str] = field(default_factory=list)

    @property
    def severity_label(self) -> str:
        """Texto legivel do nivel de risco para exibicao na interface."""
        mapping: dict[RiskLevel, str] = {
            RiskLevel.CRITICAL: "ALTO RISCO",
            RiskLevel.HIGH: "SUSPEITO MODERADO",
            RiskLevel.MEDIUM: "SUSPEITO LEVE",
            RiskLevel.LOW: "MONITORADO",
        }
        return mapping.get(self.risk_level, "DESCONHECIDO")

    @property
    def short_summary(self) -> str:
        """Linha de resumo para exibicao no painel de atividade do dashboard."""
        return (
            f"[Pre-exec] {self.severity_label} | score={self.score} | "
            f"{self.file_path.name} | acao={self.recommended_action.value}"
        )
