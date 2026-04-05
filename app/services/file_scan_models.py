"""Modelos padronizados usados pelo scanner de arquivos."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from app.core.risk import RiskLevel, ThreatClassification


@dataclass(frozen=True)
class FileScanResult:
    """Representa um arquivo sinalizado durante a verificacao."""

    path: Path
    size: int
    sha256: str
    extension: str
    heuristic_score: int
    heuristic_summary: str
    alert_reason: str
    initial_risk_level: RiskLevel
    final_classification: ThreatClassification = ThreatClassification.SUSPICIOUS
    classification_reasons: list[str] = field(default_factory=list)
    deep_scan_performed: bool = False
    deep_scan_summary: str = ""
    trusted_publisher: str | None = None
    recommended_action: str = "monitorar_e_logar"
    threat_category: str = "desconhecido"
    analysis_module: str = "file_scanner"
    detected_signals: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class FileScanError:
    """Registra problemas encontrados ao tentar acessar arquivos ou pastas."""

    path: Path
    message: str


@dataclass(frozen=True)
class FileScanReport:
    """Agrupa o resultado completo de uma execucao de varredura."""

    target_directory: Path
    scanned_files: int
    flagged_files: int
    interrupted: bool = False
    scan_label: str = "Verificacao de arquivos"
    results: list[FileScanResult] = field(default_factory=list)
    errors: list[FileScanError] = field(default_factory=list)