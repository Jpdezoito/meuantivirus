"""Rotinas de inicializacao da aplicacao."""

from __future__ import annotations

from dataclasses import dataclass
import logging

from app.core.config import AppPaths, AppSettings, build_settings, ensure_runtime_directories
from app.core.heuristics import HeuristicEngine
from app.data.database import initialize_database
from app.utils.logger import configure_logging, log_info


@dataclass(frozen=True)
class ApplicationContext:
    """Contexto compartilhado entre interface e servicos."""

    settings: AppSettings
    paths: AppPaths
    logger: logging.Logger
    heuristic_engine: HeuristicEngine


def bootstrap_application() -> ApplicationContext:
    """Prepara diretorios, logs e banco local antes da interface abrir."""
    settings = build_settings()
    paths = settings.paths

    ensure_runtime_directories(paths)

    logger = configure_logging(settings)
    heuristic_engine = HeuristicEngine()
    initialize_database(paths.database_file)
    log_info(logger, "Aplicacao inicializada com sucesso.")
    log_info(logger, f"Arquivo de log diario ativo: {paths.daily_log_file}")

    return ApplicationContext(
        settings=settings,
        paths=paths,
        logger=logger,
        heuristic_engine=heuristic_engine,
    )
