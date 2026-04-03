"""Persistencia SQLite para eventos de acoes sensiveis do operador."""

from __future__ import annotations

from pathlib import Path
import sqlite3

from app.data.action_event_models import ActionEventEntry, ActionEventRecordInput


class ActionEventRepository:
    """Grava trilha de auditoria de confirmacoes e execucoes sensiveis."""

    def __init__(self, database_file: Path) -> None:
        self.database_file = database_file

    def save_event(self, record: ActionEventRecordInput) -> ActionEventEntry:
        """Persiste um evento de acao para rastreabilidade operacional."""
        with sqlite3.connect(self.database_file) as connection:
            cursor = connection.cursor()
            cursor.execute(
                """
                INSERT INTO action_events (
                    action_id,
                    action_title,
                    severity,
                    target_summary,
                    requires_admin,
                    decision,
                    status,
                    details,
                    correlation_id
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record.action_id,
                    record.action_title,
                    record.severity,
                    record.target_summary,
                    int(record.requires_admin),
                    record.decision,
                    record.status,
                    record.details,
                    record.correlation_id,
                ),
            )
            entry_id = int(cursor.lastrowid)
            connection.commit()

        return self.get_entry(entry_id)

    def get_entry(self, entry_id: int) -> ActionEventEntry:
        """Busca um evento especifico pelo identificador persistido."""
        with sqlite3.connect(self.database_file) as connection:
            connection.row_factory = sqlite3.Row
            row = connection.execute(
                "SELECT * FROM action_events WHERE id = ?",
                (entry_id,),
            ).fetchone()

        if row is None:
            raise LookupError(f"Evento de acao nao encontrado: {entry_id}")

        return ActionEventEntry(
            id=int(row["id"]),
            created_at=row["created_at"],
            action_id=row["action_id"],
            action_title=row["action_title"],
            severity=row["severity"],
            target_summary=row["target_summary"] or "",
            requires_admin=bool(row["requires_admin"]),
            decision=row["decision"] or "",
            status=row["status"] or "",
            details=row["details"] or "",
            correlation_id=row["correlation_id"] or "",
        )