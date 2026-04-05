"""Modelos de alerta para protecao USB/BadUSB."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from app.core.risk import RiskLevel
from app.services.risk_engine import ResponseAction


@dataclass(frozen=True)
class UsbSecurityAlert:
    """Representa evento suspeito relacionado a dispositivo USB/HID."""

    kind: str
    score: int
    risk_level: RiskLevel
    recommended_action: ResponseAction
    reasons: list[str]
    categories: list[str]
    device_instance_id: str
    device_name: str
    device_class: str
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
            f"[{self.severity_label}] {self.kind} | "
            f"{self.device_name} ({self.device_class})"
        )
