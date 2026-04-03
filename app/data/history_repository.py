"""Repositorio SQLite responsavel por salvar e listar historico de verificacoes."""

from __future__ import annotations

from pathlib import Path
import sqlite3

from app.data.history_models import HistoryEntry, HistoryRecordInput


class HistoryRepository:
    """Encapsula a persistencia do historico em banco local SQLite."""

    def __init__(self, database_file: Path) -> None:
        self.database_file = database_file

    def save_result(self, record: HistoryRecordInput) -> HistoryEntry:
        """Grava no banco uma nova entrada de historico com resumo da verificacao."""
        with sqlite3.connect(self.database_file) as connection:
            cursor = connection.cursor()
            cursor.execute(
                """
                INSERT INTO scan_history (
                    scan_type,
                    target,
                    status,
                    analyzed_count,
                    suspicious_count,
                    summary,
                    report_path
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record.scan_type,
                    record.summary,
                    "completed",
                    record.analyzed_count,
                    record.suspicious_count,
                    record.summary,
                    record.report_path,
                ),
            )
            entry_id = int(cursor.lastrowid)
            connection.commit()

        return self.get_entry(entry_id)

    def list_history(self, limit: int = 100) -> list[HistoryEntry]:
        """Lista as entradas mais recentes de historico para exibicao na interface."""
        with sqlite3.connect(self.database_file) as connection:
            connection.row_factory = sqlite3.Row
            rows = connection.execute(
                """
                SELECT id, created_at, scan_type, analyzed_count, suspicious_count, summary, report_path
                FROM scan_history
                ORDER BY created_at DESC, id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()

        return [self._row_to_entry(row) for row in rows]

    def get_entry(self, entry_id: int) -> HistoryEntry:
        """Recupera uma entrada especifica do historico pelo identificador."""
        with sqlite3.connect(self.database_file) as connection:
            connection.row_factory = sqlite3.Row
            row = connection.execute(
                """
                SELECT id, created_at, scan_type, analyzed_count, suspicious_count, summary, report_path
                FROM scan_history
                WHERE id = ?
                """,
                (entry_id,),
            ).fetchone()

        if row is None:
            raise LookupError(f"Entrada de historico nao encontrada: {entry_id}")

        return self._row_to_entry(row)

    def _row_to_entry(self, row: sqlite3.Row) -> HistoryEntry:
        """Converte uma linha do SQLite em objeto do dominio de historico."""
        return HistoryEntry(
            id=int(row["id"]),
            created_at=row["created_at"],
            scan_type=row["scan_type"],
            analyzed_count=int(row["analyzed_count"] or 0),
            suspicious_count=int(row["suspicious_count"] or 0),
            summary=row["summary"] or "Resumo indisponivel.",
            report_path=row["report_path"],
        )