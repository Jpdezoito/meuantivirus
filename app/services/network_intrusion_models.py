"""Modelos de alerta para monitoramento comportamental de intrusao em rede."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from app.core.risk import RiskLevel
from app.services.risk_engine import ResponseAction


@dataclass(frozen=True)
class NetworkIntrusionAlert:
    """Representa um alerta de comportamento de ataque de rede detectado em runtime."""

    process_id: int
    process_name: str
    kind: str
    remote_ip: str
    remote_port: int
    score: int
    risk_level: RiskLevel
    recommended_action: ResponseAction
    reasons: list[str]
    categories: list[str]
    timestamp: datetime
    analysis_modules: list[str]
    blocked_ip: str | None = None
    firewall_rule_name: str | None = None

    @property
    def severity_label(self) -> str:
        if self.risk_level in (RiskLevel.CRITICAL, RiskLevel.HIGH):
            return "ALTO RISCO"
        if self.risk_level == RiskLevel.MEDIUM:
            return "SUSPEITO MODERADO"
        return "BAIXO"

    @property
    def short_summary(self) -> str:
        base = (
            f"[{self.severity_label}] {self.kind} | "
            f"{self.process_name} (PID {self.process_id}) -> {self.remote_ip}:{self.remote_port}"
        )
        if self.blocked_ip:
            return f"{base} | blocked={self.blocked_ip}"
        return base
