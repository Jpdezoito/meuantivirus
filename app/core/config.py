"""Configuracoes centrais e caminhos da aplicacao."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date
import os
from pathlib import Path
import sys

APP_NAME = "SentinelaPC"
APP_VERSION = "0.1.0"


def get_resource_base_dir() -> Path:
    """Retorna a base de recursos considerando execucao normal ou empacotada."""
    if getattr(sys, "frozen", False):
        meipass_dir = getattr(sys, "_MEIPASS", None)
        if meipass_dir:
            return Path(meipass_dir)
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parents[2]


def get_runtime_base_dir() -> Path:
    """Retorna a base de dados gravaveis considerando execucao normal ou empacotada."""
    if getattr(sys, "frozen", False):
        local_app_data = os.environ.get("LOCALAPPDATA")
        if local_app_data:
            return Path(local_app_data) / APP_NAME
        return Path.home() / "AppData" / "Local" / APP_NAME
    return Path(__file__).resolve().parents[2]


RESOURCE_BASE_DIR = get_resource_base_dir()
RUNTIME_BASE_DIR = get_runtime_base_dir()


@dataclass(frozen=True)
class AppPaths:
    """Agrupa os caminhos importantes do projeto em um unico objeto."""

    base_dir: Path
    resource_dir: Path
    app_dir: Path
    data_dir: Path
    logs_dir: Path
    quarantine_dir: Path
    reports_dir: Path
    installer_dir: Path
    database_file: Path
    daily_log_file: Path


@dataclass(frozen=True)
class AppSettings:
    """Representa as configuracoes centrais carregadas para a execucao."""

    app_name: str
    app_version: str
    paths: AppPaths


def build_daily_log_file(logs_dir: Path, reference_date: date | None = None) -> Path:
    """Monta o nome do arquivo de log diario com base na data atual."""
    current_date = reference_date or date.today()
    return logs_dir / f"sentinelapc-{current_date.isoformat()}.log"


def build_paths() -> AppPaths:
    """Monta os caminhos padrao usados pela aplicacao."""
    resource_dir = RESOURCE_BASE_DIR
    base_dir = RUNTIME_BASE_DIR
    app_dir = resource_dir / "app"
    data_dir = base_dir / "app" / "data"
    logs_dir = base_dir / "logs"
    quarantine_dir = base_dir / "quarantine"
    reports_dir = base_dir / "reports"
    installer_dir = resource_dir / "installer"

    return AppPaths(
        base_dir=base_dir,
        resource_dir=resource_dir,
        app_dir=app_dir,
        data_dir=data_dir,
        logs_dir=logs_dir,
        quarantine_dir=quarantine_dir,
        reports_dir=reports_dir,
        installer_dir=installer_dir,
        database_file=data_dir / "sentinela.db",
        daily_log_file=build_daily_log_file(logs_dir),
    )


def build_settings() -> AppSettings:
    """Cria o objeto central de configuracao da aplicacao."""
    return AppSettings(
        app_name=APP_NAME,
        app_version=APP_VERSION,
        paths=build_paths(),
    )


def ensure_runtime_directories(paths: AppPaths) -> None:
    """Garante a criacao das pastas essenciais antes da aplicacao iniciar."""
    for directory in (
        paths.logs_dir,
        paths.quarantine_dir,
        paths.reports_dir,
        paths.data_dir,
    ):
        directory.mkdir(parents=True, exist_ok=True)
