"""Servicos para auditoria e remediacao segura de extensoes do Microsoft Edge."""

from __future__ import annotations

from datetime import datetime
import json
import logging
import os
from pathlib import Path
import re
import shutil
import subprocess
from typing import Any

from app.services.edge_extension_models import (
    EdgeExtensionActionResult,
    EdgeExtensionError,
    EdgeExtensionInventory,
    EdgeExtensionRecord,
    EdgeProfileInfo,
)
from app.utils.logger import log_error, log_info, log_warning


class EdgeExtensionService:
    """Enumera, audita e remedia extensoes do Edge com validacoes fortes de caminho."""

    EDGE_PROCESS_NAME = "msedge.exe"
    EXTENSION_ID_PATTERN = re.compile(r"^[a-p]{32}$")
    EXPECTED_PROFILE_PATTERN = re.compile(r"^(Default|Profile \d+)$")
    HIGH_RISK_PERMISSIONS = {
        "proxy",
        "management",
        "webrequest",
        "webrequestblocking",
        "nativeMessaging",
        "debugger",
    }
    REVIEW_PERMISSIONS = {
        "downloads",
        "history",
        "tabs",
        "notifications",
        "cookies",
        "clipboardRead",
        "clipboardWrite",
        "storage",
    }
    EXCLUDED_USER_DATA_DIRS = {
        "Crashpad",
        "CrashpadMetrics-active.pma",
        "DawnGraphiteCache",
        "GrShaderCache",
        "ShaderCache",
        "SingletonCookie",
        "SingletonLock",
        "SingletonSocket",
        "Subresource Filter",
        "SwReporter",
        "WidevineCdm",
    }

    def __init__(self, logger: logging.Logger, data_dir: Path, quarantine_dir: Path) -> None:
        self.logger = logger
        self.data_dir = data_dir
        self.backup_root = data_dir / "browser_backups" / "edge_extensions"
        self.quarantine_root = quarantine_dir / "edge_extensions"
        self.backup_root.mkdir(parents=True, exist_ok=True)
        self.quarantine_root.mkdir(parents=True, exist_ok=True)

    def enumerate_profiles(self) -> list[EdgeProfileInfo]:
        """Localiza perfis do Edge do usuario atual em User Data."""
        user_data_dir = self._edge_user_data_dir()
        if not user_data_dir.exists():
            log_info(self.logger, f"Diretorio de perfis do Edge nao encontrado: {user_data_dir}")
            return []

        profiles: list[EdgeProfileInfo] = []
        for candidate in sorted(user_data_dir.iterdir(), key=lambda path: path.name.lower()):
            if not candidate.is_dir() or candidate.name in self.EXCLUDED_USER_DATA_DIRS:
                continue

            preferences_path = candidate / "Preferences"
            secure_preferences_path = candidate / "Secure Preferences"
            extensions_root = candidate / "Extensions"
            if not preferences_path.exists() and not extensions_root.exists():
                continue

            profiles.append(
                EdgeProfileInfo(
                    name=candidate.name,
                    path=candidate,
                    preferences_path=preferences_path,
                    secure_preferences_path=secure_preferences_path,
                    extensions_root=extensions_root,
                )
            )

        log_info(self.logger, f"Perfis do Edge enumerados: {len(profiles)}")
        return profiles

    def list_extensions(self) -> EdgeExtensionInventory:
        """Lista extensoes do Edge com metadados, caminho e estado quando disponivel."""
        profiles = self.enumerate_profiles()
        errors: list[EdgeExtensionError] = []
        extensions: list[EdgeExtensionRecord] = []

        for profile in profiles:
            preferences_data = self._read_json(profile.preferences_path, errors, required=False)
            secure_preferences_data = self._read_json(profile.secure_preferences_path, errors, required=False)
            extension_settings = self._merge_extension_settings(preferences_data, secure_preferences_data)

            if not profile.extensions_root.exists():
                log_info(self.logger, f"Perfil sem pasta de extensoes: {profile.name}")
                continue

            for extension_root in sorted(profile.extensions_root.iterdir(), key=lambda path: path.name.lower()):
                if not extension_root.is_dir():
                    continue

                resolved_root = self._safe_resolve(extension_root)
                if not self._is_path_inside(resolved_root, profile.extensions_root):
                    errors.append(
                        EdgeExtensionError(
                            source=str(extension_root),
                            message="Diretorio de extensao fora do caminho esperado do Edge.",
                        )
                    )
                    continue

                record = self._build_extension_record(profile, extension_root, extension_settings, errors)
                if record is not None:
                    extensions.append(record)
                    log_info(
                        self.logger,
                        (
                            "Extensao Edge encontrada | "
                            f"perfil={record.profile_name} | id={record.extension_id} | nome={record.name} | "
                            f"versao={record.version} | status={record.status} | caminho={record.install_path}"
                        ),
                    )

        return EdgeExtensionInventory(profiles=profiles, extensions=extensions, errors=errors)

    def is_edge_running(self) -> bool:
        """Indica se o Microsoft Edge parece estar aberto no momento."""
        try:
            completed = subprocess.run(
                ["tasklist", "/FI", f"IMAGENAME eq {self.EDGE_PROCESS_NAME}"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
        except Exception as error:
            log_warning(self.logger, f"Falha ao verificar processo do Edge: {error}")
            return False

        return self.EDGE_PROCESS_NAME.lower() in completed.stdout.lower()

    def disable_extension(
        self,
        extension: EdgeExtensionRecord,
        *,
        user_confirmed: bool = False,
    ) -> EdgeExtensionActionResult:
        """Desativa uma extensao via Preferences com backup previo e validacao posterior."""
        if not user_confirmed:
            return self._failure_result(extension, "disable", "A desativacao exige confirmacao explicita do usuario.")

        try:
            self._validate_extension_record(extension)
            operation_dir = self._create_operation_dir("disable", extension)
            backups = self._backup_preferences_files(extension, operation_dir)

            modified_files = self._set_extension_state(extension, enabled=False)
            backups.extend(path for path in modified_files if path not in backups)

            message = (
                f"Extensao '{extension.name}' desativada com sucesso no perfil '{extension.profile_name}'."
            )
            log_info(
                self.logger,
                (
                    "Extensao Edge desativada | "
                    f"perfil={extension.profile_name} | id={extension.extension_id} | backups={len(backups)}"
                ),
            )
            return EdgeExtensionActionResult(
                success=True,
                action="disable",
                message=message,
                extension_id=extension.extension_id,
                profile_name=extension.profile_name,
                original_path=extension.install_path,
                backup_paths=backups,
                warnings=self._edge_running_warning(),
            )
        except PermissionError:
            message = "Permissao insuficiente para alterar as configuracoes da extensao no Edge. Tente executar o aplicativo com privilegios adequados e feche o navegador."
            log_warning(self.logger, message)
            return self._failure_result(extension, "disable", message)
        except Exception as error:
            log_error(self.logger, "Falha ao desativar extensao do Edge.", error)
            return self._failure_result(extension, "disable", f"Nao foi possivel desativar a extensao: {error}")

    def quarantine_extension(
        self,
        extension: EdgeExtensionRecord,
        *,
        user_confirmed: bool = False,
    ) -> EdgeExtensionActionResult:
        """Move a extensao para a quarentena da aplicacao de forma reversivel."""
        return self._move_extension_out_of_edge(extension, action="quarantine", user_confirmed=user_confirmed)

    def remove_extension(
        self,
        extension: EdgeExtensionRecord,
        *,
        user_confirmed: bool = False,
    ) -> EdgeExtensionActionResult:
        """Remove a extensao do Edge movendo-a para quarentena em vez de excluir definitivamente."""
        return self._move_extension_out_of_edge(extension, action="remove", user_confirmed=user_confirmed)

    def _move_extension_out_of_edge(
        self,
        extension: EdgeExtensionRecord,
        *,
        action: str,
        user_confirmed: bool,
    ) -> EdgeExtensionActionResult:
        if not user_confirmed:
            return self._failure_result(extension, action, "A operacao exige confirmacao explicita do usuario.")

        try:
            self._validate_extension_record(extension)
            operation_dir = self._create_operation_dir(action, extension, base_dir=self.quarantine_root)
            backups = self._backup_preferences_files(extension, operation_dir)
            warnings = self._edge_running_warning()

            try:
                self._set_extension_state(extension, enabled=False)
            except Exception as error:
                warning = f"Nao foi possivel marcar a extensao como desativada antes da remocao: {error}"
                warnings.append(warning)
                log_warning(self.logger, warning)

            source_root = self._safe_resolve(extension.extension_root)
            if not source_root.exists():
                return self._failure_result(extension, action, "A pasta da extensao nao existe mais no disco.", backups=backups, warnings=warnings)

            quarantine_target = operation_dir / source_root.name
            self._write_operation_metadata(operation_dir / "metadata.json", extension, action, source_root)
            shutil.move(str(source_root), str(quarantine_target))

            if action == "remove":
                message = (
                    f"Extensao '{extension.name}' removida do Edge com seguranca e movida para a quarentena."
                )
            else:
                message = (
                    f"Extensao '{extension.name}' movida para a quarentena com sucesso."
                )

            log_info(
                self.logger,
                (
                    "Extensao Edge movida para quarentena | "
                    f"acao={action} | perfil={extension.profile_name} | id={extension.extension_id} | "
                    f"origem={source_root} | destino={quarantine_target}"
                ),
            )
            return EdgeExtensionActionResult(
                success=True,
                action=action,
                message=message,
                extension_id=extension.extension_id,
                profile_name=extension.profile_name,
                original_path=source_root,
                quarantine_path=quarantine_target,
                backup_paths=backups,
                warnings=warnings,
            )
        except PermissionError:
            message = "Permissao insuficiente para mover a extensao do Edge. Feche o navegador e tente novamente com privilegios adequados."
            log_warning(self.logger, message)
            return self._failure_result(extension, action, message)
        except Exception as error:
            log_error(self.logger, "Falha ao mover extensao do Edge para quarentena.", error)
            return self._failure_result(extension, action, f"Nao foi possivel concluir a operacao: {error}")

    def _build_extension_record(
        self,
        profile: EdgeProfileInfo,
        extension_root: Path,
        extension_settings: dict[str, dict[str, Any]],
        errors: list[EdgeExtensionError],
    ) -> EdgeExtensionRecord | None:
        extension_id = extension_root.name
        version_dir = self._pick_current_version_dir(extension_root)
        manifest_path = version_dir / "manifest.json" if version_dir is not None else None
        manifest_data: dict[str, Any] | None = None
        manifest_valid = True

        if manifest_path is not None:
            manifest_data = self._read_json(manifest_path, errors, required=True)
            manifest_valid = manifest_data is not None
        else:
            manifest_valid = False
            errors.append(EdgeExtensionError(source=str(extension_root), message="Nenhum diretorio de versao valido foi encontrado para a extensao."))

        settings_entry = extension_settings.get(extension_id, {})
        enabled, status = self._extract_status(settings_entry)

        name = extension_id
        version = version_dir.name if version_dir is not None else "desconhecida"
        description = ""
        permissions: list[str] = []
        host_permissions: list[str] = []
        metadata_missing = True
        install_path = version_dir if version_dir is not None else extension_root

        if manifest_data is not None:
            name = self._resolve_manifest_text(manifest_data.get("name"), version_dir) or extension_id
            version = str(manifest_data.get("version") or version)
            description = self._resolve_manifest_text(manifest_data.get("description"), version_dir) or ""
            permissions = self._normalize_list(manifest_data.get("permissions"))
            host_permissions = self._normalize_list(manifest_data.get("host_permissions"))
            metadata_missing = not any(manifest_data.get(key) for key in ("author", "homepage_url", "update_url"))

        expected_path_valid = self._is_path_inside(self._safe_resolve(install_path), profile.extensions_root)
        suspicious_reasons = self._audit_extension(
            profile=profile,
            extension_id=extension_id,
            name=name,
            description=description,
            version=version,
            install_path=install_path,
            permissions=permissions,
            host_permissions=host_permissions,
            manifest_valid=manifest_valid,
            settings_present=bool(settings_entry),
            metadata_missing=metadata_missing,
            expected_path_valid=expected_path_valid,
            status=status,
        )

        return EdgeExtensionRecord(
            browser="Edge",
            profile_name=profile.name,
            profile_path=profile.path,
            preferences_path=profile.preferences_path,
            secure_preferences_path=profile.secure_preferences_path,
            extension_id=extension_id,
            name=name,
            version=version,
            description=description,
            install_path=install_path,
            extension_root=extension_root,
            manifest_path=manifest_path,
            status=status,
            enabled=enabled,
            permissions=permissions,
            host_permissions=host_permissions,
            suspicious_reasons=suspicious_reasons,
            manifest_valid=manifest_valid,
            expected_path_valid=expected_path_valid,
            metadata_missing=metadata_missing,
        )

    def _audit_extension(
        self,
        *,
        profile: EdgeProfileInfo,
        extension_id: str,
        name: str,
        description: str,
        version: str,
        install_path: Path,
        permissions: list[str],
        host_permissions: list[str],
        manifest_valid: bool,
        settings_present: bool,
        metadata_missing: bool,
        expected_path_valid: bool,
        status: str,
    ) -> list[str]:
        reasons: list[str] = []

        if not self.EXTENSION_ID_PATTERN.fullmatch(extension_id):
            reasons.append("ID da extensao fora do padrao esperado do Edge/Chromium.")
        if not manifest_valid:
            reasons.append("Manifest ausente, corrompido ou inacessivel.")
        if not expected_path_valid:
            reasons.append("Diretorio da extensao fora do caminho esperado do Edge.")
        if not name or name == extension_id or len(name.strip()) <= 2 or name.startswith("__MSG_"):
            reasons.append("Nome da extensao ausente, incomum ou sem resolucao valida.")
        if not description.strip():
            reasons.append("Descricao ausente ou vazia no manifest.")
        if metadata_missing:
            reasons.append("Metadados do publisher ou origem ausentes no manifest.")
        if not settings_present:
            reasons.append("Extensao nao encontrada em Preferences/Secure Preferences do perfil.")
        if not self.EXPECTED_PROFILE_PATTERN.fullmatch(profile.name):
            reasons.append("Extensao instalada em perfil fora do padrao esperado.")
        if status == "Estado desconhecido":
            reasons.append("Nao foi possivel determinar se a extensao esta ativa ou desativada.")

        high_risk = sorted({perm for perm in permissions if perm.lower() in self.HIGH_RISK_PERMISSIONS})
        if high_risk:
            reasons.append(f"Permissoes altamente sensiveis detectadas: {', '.join(high_risk)}.")

        review_permissions = sorted({perm for perm in permissions if perm.lower() in self.REVIEW_PERMISSIONS})
        if len(review_permissions) >= 3:
            reasons.append(f"Permissoes amplas em excesso: {', '.join(review_permissions)}.")

        if any(str(item).strip() == "<all_urls>" for item in host_permissions):
            reasons.append("A extensao solicita acesso global a todos os sites (<all_urls>).")

        if not version or version == "desconhecida":
            reasons.append("Versao ausente ou nao identificada na estrutura da extensao.")

        resolved_install_path = self._safe_resolve(install_path)
        if str(resolved_install_path).lower().count("microsoft\\edge\\user data") != 1:
            reasons.append("Caminho da extensao inconsistente com a estrutura padrao do Edge.")

        return reasons

    def _backup_preferences_files(self, extension: EdgeExtensionRecord, operation_dir: Path) -> list[Path]:
        backups: list[Path] = []
        backup_dir = operation_dir / "backups"
        backup_dir.mkdir(parents=True, exist_ok=True)
        for file_path in (extension.preferences_path, extension.secure_preferences_path):
            if not file_path.exists():
                continue
            destination = backup_dir / file_path.name
            shutil.copy2(file_path, destination)
            backups.append(destination)
            log_info(self.logger, f"Backup criado antes da alteracao: {destination}")
        return backups

    def _set_extension_state(self, extension: EdgeExtensionRecord, *, enabled: bool) -> list[Path]:
        written_files: list[Path] = []
        preferences_data = self._load_required_json(extension.preferences_path)
        self._apply_extension_state(preferences_data, extension.extension_id, enabled)
        self._write_json_preserving_structure(extension.preferences_path, preferences_data)
        written_files.append(extension.preferences_path)

        if extension.secure_preferences_path.exists():
            secure_data = self._load_required_json(extension.secure_preferences_path)
            self._apply_extension_state(secure_data, extension.extension_id, enabled)
            self._write_json_preserving_structure(extension.secure_preferences_path, secure_data)
            written_files.append(extension.secure_preferences_path)

        return written_files

    def _apply_extension_state(self, blob: dict[str, Any], extension_id: str, enabled: bool) -> None:
        extensions_section = blob.setdefault("extensions", {})
        settings = extensions_section.setdefault("settings", {})
        extension_entry = settings.setdefault(extension_id, {})
        extension_entry["state"] = 1 if enabled else 0
        if enabled:
            extension_entry["disable_reasons"] = 0
            return
        extension_entry["disable_reasons"] = int(extension_entry.get("disable_reasons") or 0) | 1

    def _write_json_preserving_structure(self, path: Path, payload: dict[str, Any]) -> None:
        temp_path = path.with_suffix(path.suffix + ".tmp")
        serialized = json.dumps(payload, indent=2, ensure_ascii=False)
        temp_path.write_text(serialized, encoding="utf-8")
        json.loads(temp_path.read_text(encoding="utf-8"))
        temp_path.replace(path)

    def _write_operation_metadata(self, path: Path, extension: EdgeExtensionRecord, action: str, source_root: Path) -> None:
        payload = {
            "action": action,
            "timestamp": datetime.now().isoformat(timespec="seconds"),
            "browser": extension.browser,
            "profile": extension.profile_name,
            "extension_id": extension.extension_id,
            "name": extension.name,
            "version": extension.version,
            "description": extension.description,
            "status": extension.status,
            "origin": str(source_root),
            "install_path": str(extension.install_path),
            "manifest_path": str(extension.manifest_path) if extension.manifest_path is not None else None,
            "reasons": list(extension.suspicious_reasons),
            "permissions": list(extension.permissions),
            "host_permissions": list(extension.host_permissions),
        }
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")

    def _create_operation_dir(self, action: str, extension: EdgeExtensionRecord, base_dir: Path | None = None) -> Path:
        root = base_dir or self.backup_root
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        path = root / extension.profile_name / extension.extension_id / f"{stamp}_{action}"
        path.mkdir(parents=True, exist_ok=True)
        return path

    def _validate_extension_record(self, extension: EdgeExtensionRecord) -> None:
        if not extension.extension_id or not extension.profile_name:
            raise ValueError("Extensao sem identificacao suficiente para remediacao.")

        resolved_root = self._safe_resolve(extension.extension_root)
        if str(resolved_root).strip() == "":
            raise ValueError("Caminho vazio para a extensao selecionada.")

        if not self._is_path_inside(resolved_root, extension.profile_path / "Extensions"):
            raise ValueError("A extensao selecionada nao pertence ao diretorio oficial do Edge para este perfil.")

    def _edge_running_warning(self) -> list[str]:
        if not self.is_edge_running():
            return []
        return ["O Microsoft Edge parece estar aberto. Feche o navegador se a operacao falhar ou se o arquivo estiver bloqueado."]

    def _failure_result(
        self,
        extension: EdgeExtensionRecord,
        action: str,
        message: str,
        *,
        backups: list[Path] | None = None,
        warnings: list[str] | None = None,
    ) -> EdgeExtensionActionResult:
        return EdgeExtensionActionResult(
            success=False,
            action=action,
            message=message,
            extension_id=extension.extension_id,
            profile_name=extension.profile_name,
            original_path=extension.install_path,
            backup_paths=list(backups or []),
            warnings=list(warnings or []),
        )

    def _load_required_json(self, path: Path) -> dict[str, Any]:
        if not path.exists():
            raise FileNotFoundError(f"Arquivo nao encontrado: {path}")
        return json.loads(path.read_text(encoding="utf-8"))

    def _read_json(
        self,
        path: Path,
        errors: list[EdgeExtensionError],
        *,
        required: bool,
    ) -> dict[str, Any] | None:
        if not path.exists():
            if required:
                errors.append(EdgeExtensionError(source=str(path), message="Arquivo obrigatorio nao encontrado."))
            return None
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception as error:
            errors.append(EdgeExtensionError(source=str(path), message=f"JSON invalido ou ilegivel: {error}"))
            return None

    def _merge_extension_settings(
        self,
        preferences_data: dict[str, Any] | None,
        secure_preferences_data: dict[str, Any] | None,
    ) -> dict[str, dict[str, Any]]:
        merged: dict[str, dict[str, Any]] = {}
        for blob in (secure_preferences_data, preferences_data):
            if not isinstance(blob, dict):
                continue
            settings = blob.get("extensions", {}).get("settings", {})
            if not isinstance(settings, dict):
                continue
            for extension_id, entry in settings.items():
                if isinstance(entry, dict):
                    merged.setdefault(str(extension_id), {}).update(entry)
        return merged

    def _extract_status(self, entry: dict[str, Any]) -> tuple[bool | None, str]:
        if not entry:
            return None, "Nao registrada"
        state = entry.get("state")
        if state == 1:
            return True, "Ativa"
        if state == 0:
            return False, "Desativada"
        disable_reasons = entry.get("disable_reasons")
        if isinstance(disable_reasons, int) and disable_reasons > 0:
            return False, "Desativada"
        return None, "Estado desconhecido"

    def _resolve_manifest_text(self, raw_value: Any, version_dir: Path | None) -> str:
        if raw_value is None:
            return ""
        value = str(raw_value).strip()
        if not value.startswith("__MSG_") or version_dir is None:
            return value
        key = value.removeprefix("__MSG_").removesuffix("__")
        locales_root = version_dir / "_locales"
        if not locales_root.exists():
            return value
        for locale_dir in sorted(locales_root.iterdir(), key=lambda path: path.name.lower()):
            messages_path = locale_dir / "messages.json"
            if not messages_path.exists():
                continue
            try:
                data = json.loads(messages_path.read_text(encoding="utf-8"))
            except Exception:
                continue
            message_entry = data.get(key) or {}
            if isinstance(message_entry, dict) and message_entry.get("message"):
                return str(message_entry["message"]).strip()
        return value

    def _normalize_list(self, raw_value: Any) -> list[str]:
        if not isinstance(raw_value, list):
            return []
        return [str(item).strip() for item in raw_value if str(item).strip()]

    def _pick_current_version_dir(self, extension_root: Path) -> Path | None:
        version_dirs = [path for path in extension_root.iterdir() if path.is_dir()]
        if not version_dirs:
            return None
        version_dirs.sort(key=lambda path: self._version_key(path.name))
        return version_dirs[-1]

    def _version_key(self, raw_value: str) -> tuple[Any, ...]:
        parts = re.split(r"[._-]", raw_value)
        key: list[Any] = []
        for part in parts:
            if part.isdigit():
                key.append(int(part))
            else:
                key.append(part.lower())
        return tuple(key)

    def _edge_user_data_dir(self) -> Path:
        local_appdata = Path(os.environ.get("LOCALAPPDATA", str(Path.home() / "AppData" / "Local")))
        return local_appdata / "Microsoft" / "Edge" / "User Data"

    def _safe_resolve(self, path: Path) -> Path:
        return path.resolve(strict=False)

    def _is_path_inside(self, candidate: Path, root: Path) -> bool:
        try:
            candidate.resolve(strict=False).relative_to(root.resolve(strict=False))
            return True
        except ValueError:
            return False
