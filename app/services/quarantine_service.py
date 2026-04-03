"""Servico responsavel por isolar e restaurar arquivos em quarentena."""

from __future__ import annotations

from datetime import datetime
import hashlib
import logging
from pathlib import Path
import re
import shutil
import sqlite3

from send2trash import send2trash

from app.core.risk import RiskLevel
from app.services.quarantine_models import QuarantineItem
from app.utils.logger import log_error, log_info, log_security_event, log_warning


class QuarantineService:
    """Centraliza operacoes seguras de mover, listar e restaurar arquivos."""

    def __init__(
        self,
        quarantine_dir: Path,
        database_file: Path,
        logger: logging.Logger,
    ) -> None:
        self.quarantine_dir = quarantine_dir
        self.database_file = database_file
        self.logger = logger

    def quarantine_file(
        self,
        file_path: Path,
        reason: str,
        risk_level: RiskLevel | str,
        *,
        file_hash: str | None = None,
        user_confirmed: bool = False,
    ) -> QuarantineItem:
        """Move um arquivo para a pasta de quarentena e registra seus metadados."""
        if not user_confirmed:
            raise ValueError("A quarentena exige confirmacao explicita do usuario.")

        source_path = Path(file_path)
        if not source_path.exists() or not source_path.is_file():
            raise FileNotFoundError(f"Arquivo invalido para quarentena: {source_path}")

        normalized_reason = reason.strip() or "Arquivo sinalizado manualmente pelo usuario."
        normalized_risk = self._normalize_risk(risk_level)
        calculated_hash = file_hash or self._calculate_sha256(source_path)
        quarantined_name = self._build_quarantine_name(source_path, calculated_hash)
        quarantined_path = self.quarantine_dir / quarantined_name

        try:
            self.quarantine_dir.mkdir(parents=True, exist_ok=True)
            shutil.move(str(source_path), str(quarantined_path))
        except PermissionError as error:
            log_error(self.logger, f"Falha de permissao ao mover arquivo para quarentena: {source_path}", error)
            raise
        except OSError as error:
            log_error(self.logger, f"Falha ao mover arquivo para quarentena: {source_path}", error)
            raise

        created_at = datetime.now().isoformat(timespec="seconds")

        with sqlite3.connect(self.database_file) as connection:
            cursor = connection.cursor()
            cursor.execute(
                """
                INSERT INTO quarantine_items (
                    original_name,
                    original_path,
                    quarantined_name,
                    quarantined_path,
                    file_hash,
                    reason,
                    risk_level,
                    status,
                    created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    source_path.name,
                    str(source_path),
                    quarantined_name,
                    str(quarantined_path),
                    calculated_hash,
                    normalized_reason,
                    normalized_risk.value,
                    "quarantined",
                    created_at,
                ),
            )
            item_id = int(cursor.lastrowid)
            connection.commit()

        item = self.get_item(item_id)
        log_security_event(
            self.logger,
            (
                f"Arquivo movido para quarentena: {item.original_name} | "
                f"origem={item.original_path} | destino={item.quarantined_path} | risco={item.risk_level.value}"
            ),
        )
        return item

    def list_items(self, include_restored: bool = True) -> list[QuarantineItem]:
        """Retorna os itens registrados na quarentena, incluindo historico quando desejado."""
        query = "SELECT * FROM quarantine_items"
        params: tuple[object, ...] = ()
        if not include_restored:
            query += " WHERE status = ?"
            params = ("quarantined",)

        query += " ORDER BY created_at DESC, id DESC"

        with sqlite3.connect(self.database_file) as connection:
            connection.row_factory = sqlite3.Row
            rows = connection.execute(query, params).fetchall()

        return [self._row_to_item(row) for row in rows]

    def get_item(self, item_id: int) -> QuarantineItem:
        """Busca um item especifico pelo identificador salvo no banco."""
        with sqlite3.connect(self.database_file) as connection:
            connection.row_factory = sqlite3.Row
            row = connection.execute(
                "SELECT * FROM quarantine_items WHERE id = ?",
                (item_id,),
            ).fetchone()

        if row is None:
            raise LookupError(f"Item de quarentena nao encontrado: {item_id}")

        return self._row_to_item(row)

    def restore_item(
        self,
        item_id: int,
        *,
        user_confirmed: bool = False,
        restore_to: Path | None = None,
    ) -> QuarantineItem:
        """Restaura um item para o caminho original ou para um destino alternativo."""
        if not user_confirmed:
            raise ValueError("A restauracao exige confirmacao explicita do usuario.")

        item = self.get_item(item_id)
        if not item.is_active:
            raise ValueError("Este item ja foi restaurado anteriormente.")

        target_base = Path(restore_to) if restore_to is not None else item.original_path
        target_path = self._build_restore_path(target_base)

        try:
            target_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(item.quarantined_path), str(target_path))
        except PermissionError as error:
            log_error(self.logger, f"Falha de permissao ao restaurar item de quarentena: {item.quarantined_path}", error)
            raise
        except OSError as error:
            log_error(self.logger, f"Falha ao restaurar item de quarentena: {item.quarantined_path}", error)
            raise

        restored_at = datetime.now().isoformat(timespec="seconds")

        with sqlite3.connect(self.database_file) as connection:
            connection.execute(
                """
                UPDATE quarantine_items
                SET status = ?, restored_at = ?, original_path = ?, original_name = ?
                WHERE id = ?
                """,
                (
                    "restored",
                    restored_at,
                    str(target_path),
                    target_path.name,
                    item_id,
                ),
            )
            connection.commit()

        restored_item = self.get_item(item_id)
        log_info(
            self.logger,
            f"Item restaurado da quarentena: id={item_id} | destino={target_path}",
        )
        return restored_item

    def delete_item(
        self,
        item_id: int,
        *,
        user_confirmed: bool = False,
    ) -> QuarantineItem:
        """Envia para a Lixeira um arquivo ainda presente na quarentena."""
        if not user_confirmed:
            raise ValueError("A exclusao exige confirmacao explicita do usuario.")

        item = self.get_item(item_id)
        if item.is_deleted:
            raise ValueError("Este item ja foi excluido anteriormente.")
        if not item.is_active:
            raise ValueError("Somente itens ativos na quarentena podem ser excluidos definitivamente.")

        if item.quarantined_path.exists():
            try:
                # Mantem uma trilha segura: o arquivo vai para a Lixeira, nao para exclusao irreversivel.
                send2trash(str(item.quarantined_path))
            except PermissionError as error:
                log_error(self.logger, f"Falha de permissao ao enviar item da quarentena para a Lixeira: {item.quarantined_path}", error)
                raise
            except OSError as error:
                log_error(self.logger, f"Falha ao enviar item da quarentena para a Lixeira: {item.quarantined_path}", error)
                raise

        deleted_at = datetime.now().isoformat(timespec="seconds")

        with sqlite3.connect(self.database_file) as connection:
            connection.execute(
                """
                UPDATE quarantine_items
                SET status = ?, deleted_at = ?
                WHERE id = ?
                """,
                (
                    "deleted",
                    deleted_at,
                    item_id,
                ),
            )
            connection.commit()

        deleted_item = self.get_item(item_id)
        log_warning(
            self.logger,
            f"Item enviado para a Lixeira a partir da quarentena: id={item_id} | arquivo={item.original_name}",
        )
        return deleted_item

    def get_quarantine_dir(self) -> Path:
        """Expoe o diretorio reservado para arquivos isolados."""
        self.logger.info("Diretorio de quarentena consultado.")
        return self.quarantine_dir

    def _calculate_sha256(self, file_path: Path) -> str:
        """Calcula o hash SHA-256 do arquivo antes de movelo para isolamento."""
        digest = hashlib.sha256()
        with file_path.open("rb") as file_handle:
            for chunk in iter(lambda: file_handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    def _build_quarantine_name(self, source_path: Path, file_hash: str) -> str:
        """Gera um nome controlado e unico para armazenamento em quarentena."""
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        safe_stem = self._sanitize_name(source_path.stem)[:48] or "arquivo"
        suffix = source_path.suffix.lower()
        hash_prefix = file_hash[:12] if file_hash else "semhash"
        candidate_name = f"{timestamp}_{safe_stem}_{hash_prefix}{suffix}"
        return self._ensure_unique_name(self.quarantine_dir / candidate_name).name

    def _build_restore_path(self, requested_path: Path) -> Path:
        """Evita sobrescrever arquivos existentes durante a restauracao."""
        if not requested_path.exists():
            return requested_path

        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        alternative_name = (
            f"{requested_path.stem}_restaurado_{timestamp}{requested_path.suffix}"
        )
        candidate = requested_path.with_name(alternative_name)
        log_warning(
            self.logger,
            f"Colisao ao restaurar item de quarentena. Novo destino sugerido: {candidate}",
        )
        return self._ensure_unique_name(candidate)

    def _ensure_unique_name(self, candidate: Path) -> Path:
        """Adiciona um contador incremental quando o nome pretendido ja existe."""
        if not candidate.exists():
            return candidate

        counter = 1
        while True:
            new_name = f"{candidate.stem}_{counter}{candidate.suffix}"
            updated_candidate = candidate.with_name(new_name)
            if not updated_candidate.exists():
                return updated_candidate
            counter += 1

    def _normalize_risk(self, risk_level: RiskLevel | str) -> RiskLevel:
        """Converte entradas textuais em valores consistentes do enum de risco."""
        if isinstance(risk_level, RiskLevel):
            return risk_level

        normalized_value = str(risk_level).strip().lower()
        for option in RiskLevel:
            if option.value == normalized_value:
                return option
        return RiskLevel.LOW

    def _row_to_item(self, row: sqlite3.Row) -> QuarantineItem:
        """Transforma uma linha do banco em objeto de dominio da quarentena."""
        original_name = row["original_name"] or Path(row["original_path"]).name
        quarantined_name = row["quarantined_name"] or Path(row["quarantined_path"]).name
        risk_text = row["risk_level"] or RiskLevel.LOW.value
        return QuarantineItem(
            id=int(row["id"]),
            original_name=original_name,
            original_path=Path(row["original_path"]),
            quarantined_name=quarantined_name,
            quarantined_path=Path(row["quarantined_path"]),
            file_hash=row["file_hash"] or "",
            created_at=row["created_at"],
            reason=row["reason"] or "Motivo nao informado.",
            risk_level=self._normalize_risk(risk_text),
            status=row["status"] or "quarantined",
            restored_at=row["restored_at"],
            deleted_at=row["deleted_at"] if "deleted_at" in row.keys() else None,
        )

    def _sanitize_name(self, raw_name: str) -> str:
        """Remove caracteres problematicos para manter nomes previsiveis no Windows."""
        sanitized = re.sub(r"[^A-Za-z0-9._-]", "_", raw_name)
        return sanitized.strip("._")
