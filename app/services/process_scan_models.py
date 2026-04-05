"""Modelos padronizados usados na verificacao de processos suspeitos."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from app.core.risk import RiskLevel, ThreatClassification


@dataclass(frozen=True)
class ProcessScanResult:
    """Representa um processo sinalizado durante a analise."""

    name: str
    pid: int
    executable_path: Path | None
    cpu_usage_percent: float
    memory_usage_percent: float
    heuristic_score: int
    heuristic_summary: str
    alert_reason: str
    initial_risk_level: RiskLevel
    final_classification: ThreatClassification = ThreatClassification.SUSPICIOUS
    classification_reasons: list[str] = field(default_factory=list)
    recommended_action: str = "monitorar_e_logar"
    threat_category: str = "desconhecido"
    analysis_module: str = "process_monitor"
    detected_signals: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class ProcessScanError:
    """Registra falhas de acesso ou leitura dos processos ativos."""

    pid: int | None
    process_name: str
    message: str


@dataclass(frozen=True)
class ProcessScanReport:
    """Agrupa o resultado consolidado da verificacao de processos."""

    inspected_processes: int
    suspicious_processes: int
    interrupted: bool = False
    results: list[ProcessScanResult] = field(default_factory=list)
    errors: list[ProcessScanError] = field(default_factory=list)