"""Inicializacao do banco SQLite local."""

from __future__ import annotations

from pathlib import Path
import sqlite3


def initialize_database(database_file: Path) -> None:
    """Cria o banco e tabelas basicas usadas pela estrutura inicial."""
    database_file.parent.mkdir(parents=True, exist_ok=True)

    with sqlite3.connect(database_file) as connection:
        cursor = connection.cursor()
        cursor.executescript(
            """
            CREATE TABLE IF NOT EXISTS app_metadata (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_type TEXT NOT NULL,
                target TEXT DEFAULT '',
                status TEXT DEFAULT 'completed',
                analyzed_count INTEGER DEFAULT 0,
                suspicious_count INTEGER DEFAULT 0,
                summary TEXT,
                report_path TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS quarantine_items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                original_name TEXT,
                original_path TEXT NOT NULL,
                quarantined_name TEXT,
                quarantined_path TEXT NOT NULL,
                file_hash TEXT,
                reason TEXT,
                risk_level TEXT DEFAULT 'baixo',
                status TEXT DEFAULT 'quarantined',
                restored_at TEXT,
                deleted_at TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS diagnostic_reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                report_type TEXT NOT NULL,
                summary TEXT NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            );
            """
        )
        _migrate_scan_history_table(cursor)
        _migrate_quarantine_table(cursor)
        connection.commit()


def _migrate_scan_history_table(cursor: sqlite3.Cursor) -> None:
    """Atualiza o esquema do historico quando o banco local ja existe."""
    existing_columns = {
        row[1]
        for row in cursor.execute("PRAGMA table_info(scan_history)").fetchall()
    }

    required_columns = {
        "target": "TEXT DEFAULT ''",
        "status": "TEXT DEFAULT 'completed'",
        "analyzed_count": "INTEGER DEFAULT 0",
        "suspicious_count": "INTEGER DEFAULT 0",
        "summary": "TEXT",
        "report_path": "TEXT",
    }

    for column_name, column_definition in required_columns.items():
        if column_name in existing_columns:
            continue
        cursor.execute(
            f"ALTER TABLE scan_history ADD COLUMN {column_name} {column_definition}"
        )

    if "target" in existing_columns:
        cursor.execute(
            "UPDATE scan_history SET summary = COALESCE(summary, target) WHERE summary IS NULL"
        )
    else:
        cursor.execute(
            "UPDATE scan_history SET summary = COALESCE(summary, 'Resumo indisponivel.') WHERE summary IS NULL"
        )

    cursor.execute(
        "UPDATE scan_history SET analyzed_count = COALESCE(analyzed_count, 0) WHERE analyzed_count IS NULL"
    )
    cursor.execute(
        "UPDATE scan_history SET suspicious_count = COALESCE(suspicious_count, 0) WHERE suspicious_count IS NULL"
    )
    cursor.execute(
        "UPDATE scan_history SET target = COALESCE(target, '') WHERE target IS NULL"
    )
    cursor.execute(
        "UPDATE scan_history SET status = COALESCE(status, 'completed') WHERE status IS NULL"
    )


def _migrate_quarantine_table(cursor: sqlite3.Cursor) -> None:
    """Atualiza a tabela de quarentena quando o banco ja existe com esquema antigo."""
    existing_columns = {
        row[1]
        for row in cursor.execute("PRAGMA table_info(quarantine_items)").fetchall()
    }

    required_columns = {
        "original_name": "TEXT",
        "quarantined_name": "TEXT",
        "file_hash": "TEXT",
        "risk_level": "TEXT DEFAULT 'baixo'",
        "status": "TEXT DEFAULT 'quarantined'",
        "restored_at": "TEXT",
        "deleted_at": "TEXT",
    }

    for column_name, column_definition in required_columns.items():
        if column_name in existing_columns:
            continue
        cursor.execute(
            f"ALTER TABLE quarantine_items ADD COLUMN {column_name} {column_definition}"
        )

    cursor.execute(
        "UPDATE quarantine_items SET original_name = COALESCE(original_name, '') WHERE original_name IS NULL"
    )
    cursor.execute(
        "UPDATE quarantine_items SET quarantined_name = COALESCE(quarantined_name, '') WHERE quarantined_name IS NULL"
    )
    cursor.execute(
        "UPDATE quarantine_items SET file_hash = COALESCE(file_hash, '') WHERE file_hash IS NULL"
    )
    cursor.execute(
        "UPDATE quarantine_items SET risk_level = COALESCE(risk_level, 'baixo') WHERE risk_level IS NULL"
    )
    cursor.execute(
        "UPDATE quarantine_items SET status = COALESCE(status, 'quarantined') WHERE status IS NULL"
    )
