"""Configuracao padrao de logs da aplicacao."""

from __future__ import annotations

import logging
from logging import Logger
from pathlib import Path

from app.core.config import AppSettings

SECURITY_LEVEL = 35
logging.addLevelName(SECURITY_LEVEL, "SECURITY")


def _security(self: Logger, message: str, *args: object, **kwargs: object) -> None:
    """Adiciona ao logger um nivel proprio para eventos de seguranca."""
    if self.isEnabledFor(SECURITY_LEVEL):
        self._log(SECURITY_LEVEL, message, args, **kwargs)


if not hasattr(logging.Logger, "security"):
    logging.Logger.security = _security  # type: ignore[attr-defined]


def _build_formatter() -> logging.Formatter:
    """Cria o formatador padrao usado por todos os handlers."""
    return logging.Formatter(
        "%(asctime)s | %(levelname)s | %(name)s | %(message)s"
    )


def _build_file_handler(log_file: Path) -> logging.FileHandler:
    """Cria o handler responsavel por gravar o arquivo de log diario."""
    file_handler = logging.FileHandler(log_file, encoding="utf-8")
    file_handler.setFormatter(_build_formatter())
    return file_handler


def _build_console_handler() -> logging.StreamHandler:
    """Cria o handler de console util durante desenvolvimento e debug."""
    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(_build_formatter())
    return stream_handler


def configure_logging(settings: AppSettings) -> logging.Logger:
    """Configura o logger principal com arquivo diario e saida em console."""
    logger = logging.getLogger("sentinelapc")
    current_log_file = settings.paths.daily_log_file

    if getattr(logger, "_sentinelapc_log_file", None) == str(current_log_file):
        return logger

    for handler in list(logger.handlers):
        logger.removeHandler(handler)
        handler.close()

    logger.setLevel(logging.INFO)
    logger.addHandler(_build_file_handler(current_log_file))
    logger.addHandler(_build_console_handler())
    logger.propagate = False
    logger._sentinelapc_log_file = str(current_log_file)  # type: ignore[attr-defined]

    return logger


def log_info(logger: logging.Logger, message: str) -> None:
    """Registra uma mensagem informativa da aplicacao."""
    logger.info(message)


def log_warning(logger: logging.Logger, message: str) -> None:
    """Registra um aviso que merece atencao, sem interromper a execucao."""
    logger.warning(message)


def log_error(
    logger: logging.Logger,
    message: str,
    error: Exception | None = None,
) -> None:
    """Registra um erro e inclui detalhes extras quando houver excecao."""
    if error is None:
        logger.error(message)
        return

    logger.error("%s | detalhe: %s", message, error)


def log_security_event(logger: logging.Logger, message: str) -> None:
    """Registra um evento relevante para seguranca com nivel dedicado."""
    logger.security(message)  # type: ignore[attr-defined]
