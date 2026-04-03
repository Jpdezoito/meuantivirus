"""Modelos para analise de seguranca de navegadores."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from app.core.risk import RiskLevel, ThreatClassification


@dataclass(frozen=True)
class BrowserScanItem:
    """Representa um achado da analise de navegadores."""

    browser: str
    item_type: str
    name: str
    path: Path | None
    score: int
    risk_level: RiskLevel
    classification: ThreatClassification
    reasons: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class BrowserScanError:
    """Representa um erro de leitura durante a analise."""

    source: str
    message: str


@dataclass(frozen=True)
class BrowserScanReport:
    """Resultado consolidado da analise de navegadores."""

    inspected_items: int
    suspicious_items: int
    interrupted: bool = False
    results: list[BrowserScanItem] = field(default_factory=list)
    errors: list[BrowserScanError] = field(default_factory=list)
