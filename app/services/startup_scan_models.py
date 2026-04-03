"""Modelos padronizados usados pela verificacao de inicializacao do Windows."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from app.core.risk import RiskLevel, ThreatClassification


@dataclass(frozen=True)
class StartupScanResult:
    """Representa um item de inicializacao encontrado durante a leitura."""

    name: str
    origin: str
    command: str
    item_type: str
    heuristic_score: int
    heuristic_summary: str
    risk_level: RiskLevel
    flag_reason: str
    executable_path: Path | None = None
    final_classification: ThreatClassification = ThreatClassification.SUSPICIOUS
    classification_reasons: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class StartupScanError:
    """Registra falhas de leitura de fontes de inicializacao."""

    source: str
    message: str


@dataclass(frozen=True)
class StartupScanReport:
    """Agrupa os resultados da verificacao de inicializacao."""

    inspected_items: int
    suspicious_items: int
    interrupted: bool = False
    results: list[StartupScanResult] = field(default_factory=list)
    errors: list[StartupScanError] = field(default_factory=list)