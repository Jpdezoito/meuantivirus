"""Modelos de dados para eventos de acoes sensiveis do operador."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ActionEventRecordInput:
    """Representa um evento de acao sensivel registrado para auditoria."""

    action_id: str
    action_title: str
    severity: str
    target_summary: str
    requires_admin: bool
    decision: str
    status: str
    details: str = ""
    correlation_id: str = ""


@dataclass(frozen=True)
class ActionEventEntry:
    """Representa um evento persistido de acao sensivel."""

    id: int
    created_at: str
    action_id: str
    action_title: str
    severity: str
    target_summary: str
    requires_admin: bool
    decision: str
    status: str
    details: str
    correlation_id: str