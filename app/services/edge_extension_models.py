"""Modelos tipados para perfis, extensoes e remediacao do Microsoft Edge."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class EdgeProfileInfo:
    """Representa um perfil valido do Edge encontrado no disco."""

    name: str
    path: Path
    preferences_path: Path
    secure_preferences_path: Path
    extensions_root: Path


@dataclass(frozen=True)
class EdgeExtensionError:
    """Erro de leitura ou validacao durante a enumeracao de extensoes."""

    source: str
    message: str


@dataclass(frozen=True)
class EdgeExtensionRecord:
    """Representa uma extensao instalada em um perfil do Edge."""

    browser: str
    profile_name: str
    profile_path: Path
    preferences_path: Path
    secure_preferences_path: Path
    extension_id: str
    name: str
    version: str
    description: str
    install_path: Path
    extension_root: Path
    manifest_path: Path | None
    status: str
    enabled: bool | None
    permissions: list[str] = field(default_factory=list)
    host_permissions: list[str] = field(default_factory=list)
    suspicious_reasons: list[str] = field(default_factory=list)
    manifest_valid: bool = True
    expected_path_valid: bool = True
    metadata_missing: bool = False


@dataclass(frozen=True)
class EdgeExtensionInventory:
    """Resultado consolidado da enumeracao de perfis e extensoes do Edge."""

    profiles: list[EdgeProfileInfo] = field(default_factory=list)
    extensions: list[EdgeExtensionRecord] = field(default_factory=list)
    errors: list[EdgeExtensionError] = field(default_factory=list)


@dataclass(frozen=True)
class EdgeExtensionActionResult:
    """Retorno padronizado das acoes de remediacao aplicadas a uma extensao."""

    success: bool
    action: str
    message: str
    extension_id: str
    profile_name: str
    original_path: Path | None = None
    quarantine_path: Path | None = None
    backup_paths: list[Path] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
