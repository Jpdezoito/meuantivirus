"""Modelos de alerta para deteccao comportamental anti-ransomware/wiper."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from app.core.risk import RiskLevel
from app.services.risk_engine import ResponseAction


@dataclass(frozen=True)
class RansomwareBehaviorAlert:
    """Representa um alerta de atividade massiva suspeita em arquivos do usuario."""

    watched_root: str
    score: int
    risk_level: RiskLevel
    recommended_action: ResponseAction
    reasons: list[str]
    categories: list[str]
    changed_files: int
    created_files: int
    deleted_files: int
    suspicious_extension_hits: int
    timestamp: datetime
    analysis_modules: list[str]

    @property
    def severity_label(self) -> str:
        if self.risk_level in (RiskLevel.CRITICAL, RiskLevel.HIGH):
            return "ALTO RISCO"
        if self.risk_level == RiskLevel.MEDIUM:
            return "SUSPEITO MODERADO"
        return "BAIXO"

    @property
    def short_summary(self) -> str:
        return (
            f"[{self.severity_label}] Atividade massiva em {self.watched_root} | "
            f"mod={self.changed_files} novo={self.created_files} del={self.deleted_files}"
        )
