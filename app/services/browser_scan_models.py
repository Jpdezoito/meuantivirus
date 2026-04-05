"""Modelos para analise de seguranca de navegadores."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
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
    profile_name: str | None = None
    extension_id: str | None = None
    version: str | None = None
    status: str | None = None
    recommended_action: str = "monitorar_e_logar"
    threat_category: str = "desconhecido"
    analysis_module: str = "browser_security"
    detected_signals: list[str] = field(default_factory=list)
    original_path: Path | None = None
    detected_at: datetime | None = None
    existed_at_scan: bool | None = None
    filesystem_item_type: str | None = None


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
