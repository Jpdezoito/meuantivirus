"""Politicas de confirmacao e risco para acoes sensiveis da interface."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class ActionSeverity(StrEnum):
    """Criticidade operacional de uma acao solicitada pelo usuario."""

    NORMAL = "normal"
    SENSITIVE = "sensivel"
    HIGH = "alto"
    CRITICAL = "critico"


@dataclass(frozen=True)
class ActionPolicy:
    """Descreve como uma acao deve ser apresentada e auditada."""

    action_id: str
    title: str
    description: str
    severity: ActionSeverity
    confirm_label: str
    requires_admin: bool = False
    irreversible: bool = False
    admin_reason: str = ""
    detail_lines: tuple[str, ...] = ()
    confirm_phrase: str | None = None
    success_message: str = ""

    @property
    def severity_label(self) -> str:
        return self.severity.value.capitalize()


def build_action_policy(
    *,
    action_id: str,
    title: str,
    description: str,
    severity: ActionSeverity,
    confirm_label: str,
    requires_admin: bool = False,
    irreversible: bool = False,
    admin_reason: str = "",
    detail_lines: tuple[str, ...] = (),
    confirm_phrase: str | None = None,
    success_message: str = "",
) -> ActionPolicy:
    """Atalho declarativo para criar politicas de acao."""
    return ActionPolicy(
        action_id=action_id,
        title=title,
        description=description,
        severity=severity,
        confirm_label=confirm_label,
        requires_admin=requires_admin,
        irreversible=irreversible,
        admin_reason=admin_reason,
        detail_lines=detail_lines,
        confirm_phrase=confirm_phrase,
        success_message=success_message,
    )