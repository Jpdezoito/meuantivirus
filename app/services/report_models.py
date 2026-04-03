"""Modelos usados pela geracao de relatorios da sessao."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from app.services.file_scan_models import FileScanReport
from app.services.diagnostics_models import SystemDiagnosticsReport
from app.services.process_scan_models import ProcessScanReport
from app.services.quarantine_models import QuarantineItem
from app.services.startup_scan_models import StartupScanReport


@dataclass(frozen=True)
class SessionReportData:
    """Agrupa os dados acumulados dos scans executados na sessao atual."""

    generated_at: datetime
    executed_scan_types: list[str] = field(default_factory=list)
    file_report: FileScanReport | None = None
    process_report: ProcessScanReport | None = None
    startup_report: StartupScanReport | None = None
    diagnostics_report: SystemDiagnosticsReport | None = None
    quarantined_items: list[QuarantineItem] = field(default_factory=list)


@dataclass(frozen=True)
class GeneratedReportFiles:
    """Representa os arquivos finais gravados no disco para um relatorio."""

    txt_file: Path
    html_file: Path