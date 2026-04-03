"""Modelos de dados usados pelo historico local de verificacoes."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class HistoryEntry:
    """Representa uma entrada persistida no historico de verificacoes."""

    id: int
    created_at: str
    scan_type: str
    analyzed_count: int
    suspicious_count: int
    summary: str
    report_path: str | None = None


@dataclass(frozen=True)
class HistoryRecordInput:
    """Representa os dados minimos necessarios para registrar uma verificacao."""

    scan_type: str
    analyzed_count: int
    suspicious_count: int
    summary: str
    report_path: str | None = None