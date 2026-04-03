"""Modelos usados pelo modulo de quarentena."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from app.core.risk import RiskLevel


@dataclass(frozen=True)
class QuarantineItem:
    """Representa um arquivo isolado na pasta de quarentena."""

    id: int
    original_name: str
    original_path: Path
    quarantined_name: str
    quarantined_path: Path
    file_hash: str
    created_at: str
    reason: str
    risk_level: RiskLevel
    status: str
    restored_at: str | None = None
    deleted_at: str | None = None

    @property
    def is_active(self) -> bool:
        """Indica se o item ainda esta fisicamente em quarentena."""
        return self.status == "quarantined"

    @property
    def is_deleted(self) -> bool:
        """Indica se o item foi removido definitivamente da quarentena."""
        return self.status == "deleted"