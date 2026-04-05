"""Sentinela Mobile — antivirus para Android usando Flet 0.84+."""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
import threading
import zipfile
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import Callable, cast

import flet as ft
from flet import FilePicker


APP_NAME = "Sentinela Mobile"
APP_VERSION = "1.2.0"
MOBILE_LOGO_ASSET = "sentinelamobile.png"
MOBILE_CONFIG_FILE = Path.home() / ".sentinela_mobile" / "settings.json"
REAL_TIME_MONITOR_INTERVAL_SECONDS = 6


# ── Modelos ────────────────────────────────────────────────────────────────────

class RiskLevel(StrEnum):
    TRUSTED  = "confiavel"
    LOW      = "baixo"
    MEDIUM   = "medio"
    HIGH     = "alto"
    CRITICAL = "critico"


@dataclass
class ScanResult:
    path: Path
    name: str
    risk_level: RiskLevel
    score: int
    reasons: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class MobileModule:
    key: str
    title: str
    description: str


DESKTOP_BASE_MODULES: tuple[MobileModule, ...] = (
    MobileModule("files", "Arquivos suspeitos", "Varredura heuristica de arquivos locais."),
    MobileModule("full_scan", "Verificacao completa", "Analise ampla do armazenamento selecionado."),
    MobileModule("history", "Historico da sessao", "Registro dos eventos e acoes executadas."),
    MobileModule("startup", "Inicializacao", "Inspecao de inicializacao adaptada para mobile."),
    MobileModule("processes", "Processos", "Analise de processos ativos dentro do app."),
    MobileModule("browsers", "Navegadores", "Checagem de artefatos de navegacao exportados."),
    MobileModule("quarantine", "Quarentena", "Isolamento de itens suspeitos encontrados."),
    MobileModule("monitoring", "Monitoramento", "Observacao automatica com protecao em tempo real."),
    MobileModule("real_time", "Protecao em tempo real", "Controle manual para ligar ou desligar o monitor."),
)


# ── Regras de analise ──────────────────────────────────────────────────────────

DANGEROUS_EXTENSIONS = {
    ".apk", ".exe", ".scr", ".bat", ".cmd", ".js",
    ".vbs", ".ps1", ".jar", ".dex",
}

SUSPICIOUS_NAME_PATTERNS = [
    "crack", "hack", "keygen", "patch_", "cheat", "mod_", "_mod",
    "injector", "spyware", "trojan", "rootkit", "stalkerware",
]

DOUBLE_EXTENSION_PATTERN = re.compile(
    r"\.(pdf|jpg|jpeg|png|gif|txt|doc|docx|xls|xlsx)\.(apk|exe|scr|bat|cmd|js|vbs|ps1|jar)$",
    re.IGNORECASE,
)

# permissao -> (score, descricao legivel)
DANGEROUS_APK_PERMISSIONS: dict[str, tuple[int, str]] = {
    "android.permission.SEND_SMS":                (30, "Envia SMS sem sua confirmacao"),
    "android.permission.READ_SMS":                (25, "Le suas mensagens SMS"),
    "android.permission.RECEIVE_SMS":             (20, "Intercepta SMS recebidos"),
    "android.permission.READ_CONTACTS":           (20, "Acessa sua lista de contatos"),
    "android.permission.READ_CALL_LOG":           (25, "Le seu historico de chamadas"),
    "android.permission.PROCESS_OUTGOING_CALLS":  (25, "Intercepta chamadas realizadas"),
    "android.permission.RECORD_AUDIO":            (20, "Acessa o microfone"),
    "android.permission.ACCESS_FINE_LOCATION":    (15, "Rastreia localizacao precisa"),
    "android.permission.SYSTEM_ALERT_WINDOW":     (20, "Sobrep\u00f5e janelas sobre outros apps"),
    "android.permission.INSTALL_PACKAGES":        (35, "Instala apps sem confirmacao"),
    "android.permission.DELETE_PACKAGES":         (35, "Desinstala apps sem confirmacao"),
    "android.permission.BIND_DEVICE_ADMIN":       (40, "Solicita privilegios de administrador do dispositivo"),
    "android.permission.WRITE_EXTERNAL_STORAGE":  (15, "Escreve arquivos no armazenamento externo"),
    "android.permission.CHANGE_NETWORK_STATE":    (15, "Altera configuracoes de rede"),
    "android.permission.RECEIVE_BOOT_COMPLETED":  (20, "Inicia automaticamente com o dispositivo"),
}


def _score_to_risk(score: int) -> RiskLevel:
    if score == 0:   return RiskLevel.TRUSTED
    if score < 20:   return RiskLevel.LOW
    if score < 40:   return RiskLevel.MEDIUM
    if score < 70:   return RiskLevel.HIGH
    return RiskLevel.CRITICAL


def scan_apk_permissions(path: Path) -> tuple[int, list[str]]:
    """Extrai permissoes declaradas no APK e avalia o risco."""
    score = 0
    reasons: list[str] = []
    try:
        with zipfile.ZipFile(path, "r") as zf:
            if "AndroidManifest.xml" not in zf.namelist():
                return score, reasons
            manifest_bytes = zf.read("AndroidManifest.xml")
        # Permissoes aparecem como strings UTF-8 no binario do manifesto
        manifest_text = manifest_bytes.decode("utf-8", errors="ignore")
        for permission, (perm_score, description) in DANGEROUS_APK_PERMISSIONS.items():
            if permission in manifest_text:
                score += perm_score
                reasons.append(description)
    except (zipfile.BadZipFile, OSError):
        pass
    return score, reasons


def scan_file(path: Path) -> ScanResult:
    """Analisa um unico arquivo e retorna o resultado de risco."""
    score = 0
    reasons: list[str] = []
    ext = path.suffix.lower()

    if ext in DANGEROUS_EXTENSIONS:
        score += 30
        reasons.append(f"Extensao potencialmente perigosa: {ext}")

    if DOUBLE_EXTENSION_PATTERN.search(path.name):
        score += 35
        reasons.append("Arquivo com dupla extensao, possivel tentativa de mascaramento")

    if ext == ".apk":
        apk_score, apk_reasons = scan_apk_permissions(path)
        score += apk_score
        reasons.extend(apk_reasons)

    name_lower = path.name.lower()
    for pattern in SUSPICIOUS_NAME_PATTERNS:
        if pattern in name_lower:
            score += 20
            reasons.append(f"Nome contem padrao suspeito: '{pattern}'")
            break

    try:
        age_hours = (datetime.now().timestamp() - path.stat().st_mtime) / 3600
        if age_hours < 24 and ext in DANGEROUS_EXTENSIONS:
            score += 15
            reasons.append("Arquivo perigoso baixado ou modificado recentemente")

        size_bytes = path.stat().st_size
        if ext in {".bat", ".cmd", ".ps1", ".vbs", ".js"} and size_bytes > 5 * 1024 * 1024:
            score += 15
            reasons.append("Script com tamanho anormalmente alto")
    except OSError:
        pass

    return ScanResult(path=path, name=path.name, risk_level=_score_to_risk(score), score=score, reasons=reasons)


def scan_directory(
    directory: Path,
    progress_callback: Callable[[int, int], None] | None = None,
    cancel_flag: list[bool] | None = None,
) -> tuple[list[ScanResult], int]:
    """Varre uma pasta e retorna (suspeitos, total_arquivos)."""
    all_files = [f for f in directory.rglob("*") if f.is_file()]
    total = len(all_files)
    suspicious: list[ScanResult] = []
    for index, file_path in enumerate(all_files):
        if cancel_flag and cancel_flag[0]:
            break
        if progress_callback:
            progress_callback(index + 1, total)
        result = scan_file(file_path)
        if result.score > 0:
            suspicious.append(result)
    return suspicious, total


def compute_sha256(path: Path) -> str:
    """Calcula SHA-256 de um arquivo."""
    hasher = hashlib.sha256()
    try:
        with path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                hasher.update(chunk)
        return hasher.hexdigest()
    except OSError as error:
        return f"Erro: {error}"


# ── Tema / cores ───────────────────────────────────────────────────────────────

BG       = "#111827"
CARD     = "#1e2d3d"
ACCENT   = "#3b9eff"
TEXT1    = "#f0f6ff"
TEXT2    = "#8ba3bb"
DANGER   = "#ef4444"
SUCCESS  = "#22c55e"
WARNING  = "#f59e0b"
ORANGE   = "#f97316"

RISK_COLORS: dict[RiskLevel, str] = {
    RiskLevel.TRUSTED:  SUCCESS,
    RiskLevel.LOW:      "#64748b",
    RiskLevel.MEDIUM:   WARNING,
    RiskLevel.HIGH:     ORANGE,
    RiskLevel.CRITICAL: DANGER,
}


def _card(content: ft.Control, padding: int = 16) -> ft.Container:
    return ft.Container(content=content, bgcolor=CARD, border_radius=12, padding=padding)


def _label(text: str) -> ft.Text:
    return ft.Text(text, size=11, color=TEXT2, weight=ft.FontWeight.W_600)


def _risk_chip(risk: RiskLevel) -> ft.Container:
    color = RISK_COLORS.get(risk, TEXT2)
    return ft.Container(
        content=ft.Text(risk.value.upper(), size=9, color=color, weight=ft.FontWeight.W_700),
        border=ft.border.all(1, color),
        border_radius=6,
        padding=ft.padding.symmetric(horizontal=8, vertical=2),
    )


# ── App ────────────────────────────────────────────────────────────────────────

async def main(page: ft.Page) -> None:
    page.title       = APP_NAME
    page.bgcolor     = BG
    page.padding     = 0
    page.theme_mode  = ft.ThemeMode.DARK
    page.window.width  = 420
    page.window.height = 860

    # estado mutavel
    _results:     list[ScanResult]  = []
    _is_scanning: list[bool]        = [False]
    _cancel:      list[bool]        = [False]
    _sel_dir:     list[Path | None] = [None]
    _hashes:      dict[str, str]    = {}
    _desktop_modules: list[MobileModule] = []
    _module_runtime_status: dict[str, str] = {}
    _module_cards_column = ft.Column(spacing=8, tight=True)
    _history_list = ft.ListView(controls=[], spacing=6, height=170)
    _real_time_protection_enabled: list[bool] = [True]
    _real_time_monitor_generation: list[int] = [0]
    _monitor_task_running: list[bool] = [False]
    _snapshot_state: dict[str, float] = {}
    _reported_real_time_items: set[str] = set()

    # ── Referencias de controles dinâmicos ────────────────────────────────

    status_txt      = ft.Text("Pronto para verificar", size=12, color=TEXT2)
    progress_ring   = ft.ProgressRing(visible=False, color=ACCENT, width=20, height=20)
    progress_bar    = ft.ProgressBar(visible=False, color=ACCENT, bgcolor=CARD, value=0, expand=True)
    progress_lbl    = ft.Text("", size=11, color=TEXT2)
    protection_state_txt = ft.Text("", size=11, weight=ft.FontWeight.W_600)
    monitor_state_txt = ft.Text("", size=11, color=TEXT2)
    module_section_desc = ft.Text("", size=11, color=TEXT2)
    protection_switch = ft.Switch(value=True, active_color=SUCCESS, inactive_thumb_color="#8ba3bb")

    def _append_history_log(message: str) -> None:
        timestamp = datetime.now().strftime("%H:%M:%S")
        _history_list.controls.insert(
            0,
            ft.Text(f"[{timestamp}] {message}", size=11, color=TEXT2),
        )
        if len(_history_list.controls) > 80:
            _history_list.controls.pop()

    def _load_mobile_config() -> dict[str, bool]:
        default = {"real_time_protection_enabled": True}
        try:
            if not MOBILE_CONFIG_FILE.exists():
                return default
            raw = json.loads(MOBILE_CONFIG_FILE.read_text(encoding="utf-8"))
            enabled = bool(raw.get("real_time_protection_enabled", True))
            return {"real_time_protection_enabled": enabled}
        except (OSError, json.JSONDecodeError, TypeError, ValueError):
            return default

    def _save_mobile_config() -> None:
        payload = {"real_time_protection_enabled": _real_time_protection_enabled[0]}
        MOBILE_CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
        MOBILE_CONFIG_FILE.write_text(json.dumps(payload, ensure_ascii=True, indent=2), encoding="utf-8")

    def sync_mobile_with_desktop_modules() -> list[MobileModule]:
        """Mantem o conjunto de modulos mobile alinhado ao baseline do desktop."""
        return list(DESKTOP_BASE_MODULES)

    def load_mobile_modules() -> None:
        """Carrega os modulos principais e aplica status iniciais para mobile."""
        _desktop_modules.clear()
        _desktop_modules.extend(sync_mobile_with_desktop_modules())
        _module_runtime_status.clear()
        for module in _desktop_modules:
            _module_runtime_status[module.key] = "ativo"
        if not _real_time_protection_enabled[0]:
            _module_runtime_status["monitoring"] = "desativado"
            _module_runtime_status["real_time"] = "desativado"

    def _status_color(status: str) -> str:
        if status == "ativo":
            return SUCCESS
        if status == "desativado":
            return WARNING
        return TEXT2

    def _render_module_cards() -> None:
        _module_cards_column.controls.clear()
        for module in _desktop_modules:
            runtime_status = _module_runtime_status.get(module.key, "ativo")
            chip = ft.Container(
                content=ft.Text(runtime_status.upper(), size=9, weight=ft.FontWeight.W_700, color=_status_color(runtime_status)),
                border=ft.border.all(1, _status_color(runtime_status)),
                border_radius=8,
                padding=ft.padding.symmetric(horizontal=8, vertical=2),
            )
            _module_cards_column.controls.append(
                _card(
                    ft.Row(
                        controls=[
                            ft.Column(
                                controls=[
                                    ft.Text(module.title, size=13, color=TEXT1, weight=ft.FontWeight.W_600),
                                    ft.Text(module.description, size=10, color=TEXT2),
                                ],
                                spacing=2,
                                expand=True,
                            ),
                            chip,
                        ],
                        spacing=10,
                        vertical_alignment=ft.CrossAxisAlignment.CENTER,
                    ),
                    padding=12,
                )
            )

    async def _real_time_monitor_loop(generation: int) -> None:
        """Loop de monitoramento em tempo real com controle de geracao para evitar duplicacoes."""
        try:
            while _real_time_protection_enabled[0] and generation == _real_time_monitor_generation[0]:
                selected_dir = _sel_dir[0]
                if selected_dir and selected_dir.exists():
                    changed_files: list[Path] = []
                    scanned = 0
                    for file_path in selected_dir.rglob("*"):
                        if not file_path.is_file():
                            continue
                        scanned += 1
                        if scanned > 1200:
                            break
                        key = str(file_path)
                        try:
                            modified = file_path.stat().st_mtime
                        except OSError:
                            continue
                        prev = _snapshot_state.get(key)
                        if prev is None or modified > prev:
                            _snapshot_state[key] = modified
                            changed_files.append(file_path)

                    suspicious_hits = 0
                    for candidate in changed_files[:20]:
                        result = scan_file(candidate)
                        if result.score <= 0:
                            continue
                        unique_key = f"{candidate}:{result.score}"
                        if unique_key in _reported_real_time_items:
                            continue
                        _reported_real_time_items.add(unique_key)
                        suspicious_hits += 1
                        _results.insert(0, result)
                        results_list.controls.insert(0, _build_item(result))

                    if suspicious_hits > 0:
                        val_suspeitos.value = str(len(_results))
                        _append_history_log(
                            f"[Monitoramento] {suspicious_hits} item(ns) suspeito(s) detectado(s) automaticamente."
                        )
                        status_txt.value = "Monitoramento em tempo real detectou novos riscos."
                        _module_runtime_status["monitoring"] = "ativo"
                        _render_module_cards()
                        page.update()

                await asyncio.sleep(REAL_TIME_MONITOR_INTERVAL_SECONDS)
        finally:
            if generation == _real_time_monitor_generation[0]:
                _monitor_task_running[0] = False

    def update_mobile_protection_ui() -> None:
        """Sincroniza switch, status textual e estado dos modulos monitorados."""
        enabled = _real_time_protection_enabled[0]
        protection_switch.value = enabled
        if enabled:
            protection_state_txt.value = "Protecao ativada"
            protection_state_txt.color = SUCCESS
            monitor_state_txt.value = "Monitor: ativo"
            module_section_desc.value = "Modulos alinhados ao desktop e monitoramento automatico ativo."
            _module_runtime_status["monitoring"] = "ativo"
            _module_runtime_status["real_time"] = "ativo"
        else:
            protection_state_txt.value = "Protecao desativada"
            protection_state_txt.color = WARNING
            monitor_state_txt.value = "Monitor: desativado"
            module_section_desc.value = "Monitoramento automatico pausado por escolha do usuario."
            _module_runtime_status["monitoring"] = "desativado"
            _module_runtime_status["real_time"] = "desativado"
        _render_module_cards()

    def _ensure_monitor_loop() -> None:
        if not _real_time_protection_enabled[0] or _monitor_task_running[0]:
            return
        _monitor_task_running[0] = True
        generation = _real_time_monitor_generation[0]
        page.run_task(_real_time_monitor_loop, generation)

    def enable_real_time_protection() -> None:
        """Ativa a protecao em tempo real e inicia os loops de monitoramento necessarios."""
        if _real_time_protection_enabled[0]:
            return
        _real_time_protection_enabled[0] = True
        _real_time_monitor_generation[0] += 1
        _save_mobile_config()
        update_mobile_protection_ui()
        _append_history_log("[Protecao] Protecao em tempo real ativada pelo usuario.")
        _ensure_monitor_loop()
        page.update()

    def disable_real_time_protection() -> None:
        """Desativa com seguranca os monitores automaticos de protecao em tempo real."""
        if not _real_time_protection_enabled[0]:
            return
        _real_time_protection_enabled[0] = False
        _real_time_monitor_generation[0] += 1
        _monitor_task_running[0] = False
        _save_mobile_config()
        update_mobile_protection_ui()
        _append_history_log("[Protecao] Protecao em tempo real desativada pelo usuario.")
        page.update()

    def toggle_real_time_protection() -> None:
        """Alterna manualmente o estado real da protecao e sincroniza UI + monitor."""
        if _real_time_protection_enabled[0]:
            disable_real_time_protection()
        else:
            enable_real_time_protection()

    config = _load_mobile_config()
    _real_time_protection_enabled[0] = bool(config.get("real_time_protection_enabled", True))
    _real_time_monitor_generation[0] = 1
    load_mobile_modules()

    val_analisados  = ft.Text("0", size=26, weight=ft.FontWeight.BOLD, color=ACCENT)
    val_suspeitos   = ft.Text("0", size=26, weight=ft.FontWeight.BOLD, color=DANGER)

    dir_txt         = ft.Text("Nenhuma pasta selecionada", size=12, color=TEXT2, expand=True, overflow=ft.TextOverflow.ELLIPSIS)
    results_list    = ft.ListView(controls=[], spacing=8, expand=True, padding=ft.padding.symmetric(horizontal=16))

    scan_btn        = ft.ElevatedButton(
        content="Iniciar verificacao",
        icon=ft.Icons.PLAY_ARROW_ROUNDED,
        bgcolor=ACCENT, color=TEXT1,
        height=52, expand=True,
    )
    stop_btn        = ft.ElevatedButton(
        content="Parar",
        icon=ft.Icons.STOP_ROUNDED,
        bgcolor=DANGER, color=TEXT1,
        height=52, visible=False,
    )
    full_scan_btn   = ft.ElevatedButton(
        content="Verificacao completa",
        icon=ft.Icons.RADAR_ROUNDED,
        bgcolor="#1d3461", color=TEXT1,
        height=52, expand=True,
    )

    # ── Construtor de item de resultado ───────────────────────────────────

    def _build_item(result: ScanResult) -> ft.Control:
        reasons_text = "\n".join(f"• {r}" for r in result.reasons) or "Sem motivos detalhados"
        hash_lbl = ft.Text("", size=10, color=TEXT2, selectable=True, expand=True)
        key = str(result.path)

        def _calc_hash() -> None:
            if key not in _hashes:
                hash_lbl.value = "Calculando..."
                page.update()
                _hashes[key] = compute_sha256(result.path)
            hash_lbl.value = _hashes[key]
            page.update()

        row_top: list[ft.Control] = [
            ft.Icon(ft.Icons.WARNING_AMBER_ROUNDED,
                    color=RISK_COLORS.get(result.risk_level, WARNING), size=18),
            ft.Text(result.name, size=13, weight=ft.FontWeight.W_600,
                    color=TEXT1, expand=True, overflow=ft.TextOverflow.ELLIPSIS),
            _risk_chip(result.risk_level),
        ]
        row_hash: list[ft.Control] = [
            ft.TextButton(
                content="Calcular SHA-256",
                style=ft.ButtonStyle(color=ACCENT),
                on_click=_calc_hash,
            ),
            hash_lbl,
        ]
        col_controls: list[ft.Control] = [
            ft.Row(controls=row_top, spacing=8, vertical_alignment=ft.CrossAxisAlignment.CENTER),
            ft.Text(str(result.path), size=10, color=TEXT2, overflow=ft.TextOverflow.ELLIPSIS),
            ft.Text(f"Score: {result.score}", size=11, color=TEXT2),
            ft.Text(reasons_text, size=11, color=TEXT2),
            ft.Row(controls=row_hash, spacing=6, wrap=True),
        ]
        return _card(ft.Column(controls=col_controls, spacing=5, tight=True), padding=14)

    # ── Logica do scan ────────────────────────────────────────────────────

    def _on_progress(done: int, total: int) -> None:
        progress_bar.value = done / total if total else 0
        progress_lbl.value = f"{done} / {total} arquivos"
        page.update()

    def _run_scan() -> None:
        directory = _sel_dir[0]
        if directory is None:
            return
        results, total = scan_directory(directory, _on_progress, _cancel)
        results.sort(key=lambda r: -r.score)
        _results.clear()
        _results.extend(results)
        results_list.controls.clear()
        for r in results:
            results_list.controls.append(_build_item(r))
        val_analisados.value = str(total)
        val_suspeitos.value  = str(len(results))
        progress_ring.visible = False
        progress_bar.value    = 1
        suffix = "interrompida" if _cancel[0] else "concluida"
        status_txt.value      = f"Verificacao {suffix} — {len(results)} suspeito(s)."
        _module_runtime_status["files"] = "ativo"
        _module_runtime_status["full_scan"] = "ativo"
        _module_runtime_status["history"] = "ativo"
        _render_module_cards()
        _append_history_log(
            f"[Scan] Verificacao {suffix}. Arquivos analisados: {total}. Suspeitos: {len(results)}."
        )
        scan_btn.visible      = True
        full_scan_btn.visible = True
        stop_btn.visible      = False
        _is_scanning[0]       = False
        page.update()

    def _do_start_scan() -> None:
        _is_scanning[0]       = True
        _cancel[0]            = False
        results_list.controls.clear()
        val_analisados.value  = "0"
        val_suspeitos.value   = "0"
        progress_ring.visible = True
        progress_bar.visible  = True
        progress_bar.value    = 0
        progress_lbl.value    = ""
        status_txt.value      = "Verificando..."
        _append_history_log("[Scan] Nova verificacao iniciada manualmente.")
        scan_btn.visible      = False
        full_scan_btn.visible = False
        stop_btn.visible      = True
        page.update()
        threading.Thread(target=_run_scan, daemon=True).start()

    def _start_scan() -> None:
        if _is_scanning[0]:
            return
        if _sel_dir[0] is None:
            status_txt.value = "Selecione uma pasta antes de iniciar."
            page.update()
            return
        _do_start_scan()

    def _start_full_scan() -> None:
        if _is_scanning[0]:
            return
        _sel_dir[0]   = Path.home()
        dir_txt.value = "Verificacao completa"
        _append_history_log("[Scan] Verificacao completa iniciada com escopo padrao do dispositivo.")
        _do_start_scan()

    def _stop_scan() -> None:
        _cancel[0] = True
        status_txt.value = "Parando verificacao..."
        _append_history_log("[Scan] Solicitacao de parada recebida.")
        page.update()

    scan_btn.on_click      = _start_scan
    full_scan_btn.on_click = _start_full_scan
    stop_btn.on_click      = _stop_scan
    protection_switch.on_change = lambda _event: toggle_real_time_protection()

    # ── Seletor de pasta ──────────────────────────────────────────────────

    file_picker = FilePicker()
    page.services.append(file_picker)

    async def _pick_directory() -> None:
        path = await file_picker.get_directory_path(dialog_title="Selecione a pasta para verificar")
        if path:
            _sel_dir[0] = Path(path)
            dir_txt.value = path
            _module_runtime_status["startup"] = "ativo"
            _module_runtime_status["processes"] = "ativo"
            _module_runtime_status["browsers"] = "ativo"
            _module_runtime_status["quarantine"] = "ativo"
            _render_module_cards()
            _append_history_log(f"[Sessao] Pasta selecionada para monitoramento: {path}")
            _ensure_monitor_loop()
        page.update()

    # ── Layout ────────────────────────────────────────────────────────────

    header = ft.Container(
        content=ft.Row(
            controls=[
                ft.Container(
                    content=ft.Image(
                        src=MOBILE_LOGO_ASSET,
                        width=112,
                        height=112,
                    ),
                    width=104,
                    height=104,
                    alignment=ft.Alignment(0, 0),
                    border_radius=24,
                    clip_behavior=ft.ClipBehavior.HARD_EDGE,
                ),
                ft.Column(
                    controls=[
                        ft.Text("Sentinela Mobile", size=19, weight=ft.FontWeight.BOLD, color=TEXT1),
                        ft.Text(f"Protecao mobile v{APP_VERSION}", size=12, color=TEXT2),
                        monitor_state_txt,
                    ],
                    spacing=4,
                    tight=True,
                    alignment=ft.MainAxisAlignment.CENTER,
                    expand=True,
                ),
                _card(
                    ft.Column(
                        controls=[
                            protection_state_txt,
                            ft.Row(
                                controls=[
                                    ft.Text("Tempo real", size=11, color=TEXT2),
                                    protection_switch,
                                ],
                                spacing=8,
                                alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                                vertical_alignment=ft.CrossAxisAlignment.CENTER,
                            ),
                        ],
                        spacing=4,
                        tight=True,
                    ),
                    padding=10,
                ),
            ],
            spacing=20,
            vertical_alignment=ft.CrossAxisAlignment.CENTER,
        ),
        bgcolor=CARD,
        padding=ft.padding.symmetric(horizontal=20, vertical=22),
    )

    folder_row_controls: list[ft.Control] = [
        cast(ft.Control, dir_txt),
        cast(
            ft.Control,
            ft.Container(
                content=ft.Icon(ft.Icons.FOLDER_OPEN_ROUNDED, color=ACCENT),
                tooltip="Selecionar pasta",
                ink=True,
                padding=8,
                border_radius=10,
                on_click=lambda _event: page.run_task(_pick_directory),
            ),
        ),
    ]

    folder_controls: list[ft.Control] = [
        cast(ft.Control, _label("PASTA PARA VERIFICAR")),
        cast(
            ft.Control,
            ft.Row(
                controls=folder_row_controls,
                spacing=4,
            ),
        ),
    ]

    folder_card = _card(
        ft.Column(
            controls=folder_controls,
            spacing=8,
            tight=True,
        )
    )

    modules_card = _card(
        ft.Column(
            controls=[
                _label("MODULOS PRINCIPAIS (BASE DESKTOP)"),
                module_section_desc,
                _module_cards_column,
            ],
            spacing=8,
            tight=True,
        ),
        padding=14,
    )

    history_card = _card(
        ft.Column(
            controls=[
                _label("HISTORICO DA SESSAO"),
                _history_list,
            ],
            spacing=8,
            tight=True,
        ),
        padding=14,
    )

    metrics_row = ft.Row(
        controls=[
            ft.Container(
                _card(ft.Column(controls=[val_analisados, _label("ANALISADOS")], spacing=4, tight=True)),
                expand=True,
            ),
            ft.Container(
                _card(ft.Column(controls=[val_suspeitos, _label("SUSPEITOS")], spacing=4, tight=True)),
                expand=True,
            ),
        ],
        spacing=12,
    )

    progress_card = _card(
        ft.Column(
            controls=[
                ft.Row(
                    controls=[progress_ring, status_txt],
                    spacing=10,
                    vertical_alignment=ft.CrossAxisAlignment.CENTER,
                ),
                ft.Row(controls=[progress_bar], expand=False),
                progress_lbl,
            ],
            spacing=6, tight=True,
        )
    )

    buttons_col = ft.Column(
        controls=[
            ft.Row(controls=[scan_btn, full_scan_btn], spacing=8),
            ft.Row(controls=[stop_btn], alignment=ft.MainAxisAlignment.CENTER),
        ],
        spacing=8, tight=True,
    )

    body = ft.Column(
        controls=[
            ft.Container(height=12),
            ft.Container(modules_card,   padding=ft.padding.symmetric(horizontal=16)),
            ft.Container(height=10),
            ft.Container(folder_card,    padding=ft.padding.symmetric(horizontal=16)),
            ft.Container(height=10),
            ft.Container(metrics_row,    padding=ft.padding.symmetric(horizontal=16)),
            ft.Container(height=10),
            ft.Container(
                _card(buttons_col),
                padding=ft.padding.symmetric(horizontal=16),
            ),
            ft.Container(height=10),
            ft.Container(progress_card,  padding=ft.padding.symmetric(horizontal=16)),
            ft.Container(height=10),
            ft.Container(history_card,   padding=ft.padding.symmetric(horizontal=16)),
            ft.Container(height=14),
            ft.Container(
                ft.Text("ITENS SUSPEITOS", size=11, color=TEXT2, weight=ft.FontWeight.W_600),
                padding=ft.padding.symmetric(horizontal=16),
            ),
            ft.Container(height=6),
            results_list,
            ft.Container(height=16),
        ],
        spacing=0,
        scroll=ft.ScrollMode.AUTO,
        expand=True,
    )

    page.add(
        ft.Column(
            controls=[header, body],
            spacing=0,
            expand=True,
        )
    )

    update_mobile_protection_ui()
    _append_history_log("[Sessao] Modulos desktop adaptados carregados no mobile.")
    if _real_time_protection_enabled[0]:
        _append_history_log("[Protecao] Protecao em tempo real restaurada como ativada.")
        _ensure_monitor_loop()
    else:
        _append_history_log("[Protecao] Protecao em tempo real restaurada como desativada.")
    page.update()


if __name__ == "__main__":
    ft.app(target=main, assets_dir="assets")
