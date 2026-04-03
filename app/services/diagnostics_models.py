"""Modelos usados pelo modulo de diagnostico de saude do sistema."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from app.services.startup_scan_models import StartupScanReport


@dataclass(frozen=True)
class HeavyProcessEntry:
    """Representa um processo com maior impacto atual no desempenho."""

    name: str
    pid: int
    cpu_usage_percent: float
    memory_usage_percent: float
    executable_path: Path | None


@dataclass(frozen=True)
class DiagnosticIssue:
    """Representa um achado relevante para a saude geral do PC."""

    category: str
    severity: str
    message: str


@dataclass(frozen=True)
class DiagnosticPathError:
    """Representa erros simples de acesso ou caminhos invalidos observados nos scans."""

    source: str
    location: str
    message: str


@dataclass(frozen=True)
class SystemDiagnosticsReport:
    """Consolida o panorama atual de saude e desempenho do computador."""

    generated_at: datetime
    cpu_usage_percent: float
    memory_usage_percent: float
    disk_usage_percent: float
    free_disk_gb: float
    total_disk_gb: float
    startup_items_count: int
    interrupted: bool = False
    startup_programs: list[str] = field(default_factory=list)
    heavy_processes: list[HeavyProcessEntry] = field(default_factory=list)
    slowdown_signals: list[str] = field(default_factory=list)
    path_errors: list[DiagnosticPathError] = field(default_factory=list)
    issues: list[DiagnosticIssue] = field(default_factory=list)
    # Guarda os dados de startup usados no diagnostico para reutilizar em quarentena.
    startup_report_used: StartupScanReport | None = None