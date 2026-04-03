"""Modelos para analise local de e-mails exportados e anexos."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from app.core.risk import RiskLevel, ThreatClassification


@dataclass(frozen=True)
class EmailScanItem:
    """Representa um item de e-mail analisado com score de risco."""

    source_file: Path
    subject: str
    sender: str
    links_found: int
    attachments_found: int
    score: int
    risk_level: RiskLevel
    classification: ThreatClassification
    reasons: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class EmailScanError:
    """Representa erro de leitura/parse de arquivo de e-mail."""

    source: Path
    message: str


@dataclass(frozen=True)
class EmailScanReport:
    """Resultado consolidado da analise local de e-mails."""

    inspected_items: int
    suspicious_items: int
    interrupted: bool = False
    results: list[EmailScanItem] = field(default_factory=list)
    errors: list[EmailScanError] = field(default_factory=list)
