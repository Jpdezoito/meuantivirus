"""SentinelaPC Mobile — antivirus para Android usando Flet 0.84+."""

from __future__ import annotations

import hashlib
import threading
import zipfile
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import Callable

import flet as ft
from flet import FilePicker


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


# ── Regras de analise ──────────────────────────────────────────────────────────

DANGEROUS_EXTENSIONS = {
    ".apk", ".exe", ".scr", ".bat", ".cmd", ".js",
    ".vbs", ".ps1", ".jar", ".dex",
}

SUSPICIOUS_NAME_PATTERNS = [
    "crack", "hack", "keygen", "patch_", "cheat", "mod_", "_mod",
    "injector", "spyware", "trojan", "rootkit", "stalkerware",
]

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
    page.title       = "SentinelaPC Mobile"
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

    # ── Referencias de controles dinâmicos ────────────────────────────────

    status_txt      = ft.Text("Pronto para verificar", size=12, color=TEXT2)
    progress_ring   = ft.ProgressRing(visible=False, color=ACCENT, width=20, height=20)
    progress_bar    = ft.ProgressBar(visible=False, color=ACCENT, bgcolor=CARD, value=0, expand=True)
    progress_lbl    = ft.Text("", size=11, color=TEXT2)

    val_analisados  = ft.Text("0", size=26, weight=ft.FontWeight.BOLD, color=ACCENT)
    val_suspeitos   = ft.Text("0", size=26, weight=ft.FontWeight.BOLD, color=DANGER)

    dir_txt         = ft.Text("Nenhuma pasta selecionada", size=12, color=TEXT2, expand=True, overflow=ft.TextOverflow.ELLIPSIS)
    results_list    = ft.ListView(spacing=8, expand=True, padding=ft.padding.symmetric(horizontal=16))

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
            ft.Row(row_top, spacing=8, vertical_alignment=ft.CrossAxisAlignment.CENTER),
            ft.Text(str(result.path), size=10, color=TEXT2, overflow=ft.TextOverflow.ELLIPSIS),
            ft.Text(f"Score: {result.score}", size=11, color=TEXT2),
            ft.Text(reasons_text, size=11, color=TEXT2),
            ft.Row(row_hash, spacing=6, wrap=True),
        ]
        return _card(ft.Column(col_controls, spacing=5, tight=True), padding=14)

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
        _do_start_scan()

    def _stop_scan() -> None:
        _cancel[0] = True
        status_txt.value = "Parando verificacao..."
        page.update()

    scan_btn.on_click      = _start_scan
    full_scan_btn.on_click = _start_full_scan
    stop_btn.on_click      = _stop_scan

    # ── Seletor de pasta ──────────────────────────────────────────────────

    file_picker = FilePicker()
    page.services.append(file_picker)

    async def _pick_directory() -> None:
        path = await file_picker.get_directory_path(dialog_title="Selecione a pasta para verificar")
        if path:
            _sel_dir[0] = Path(path)
            dir_txt.value = path
        page.update()

    # ── Layout ────────────────────────────────────────────────────────────

    header = ft.Container(
        content=ft.Row(
            [
                ft.Icon(ft.Icons.SECURITY_ROUNDED, color=ACCENT, size=28),
                ft.Column(
                    [
                        ft.Text("SentinelaPC", size=17, weight=ft.FontWeight.BOLD, color=TEXT1),
                        ft.Text("Protecao mobile", size=11, color=TEXT2),
                    ],
                    spacing=0, tight=True,
                ),
            ],
            spacing=12,
            vertical_alignment=ft.CrossAxisAlignment.CENTER,
        ),
        bgcolor=CARD,
        padding=ft.padding.symmetric(horizontal=20, vertical=14),
    )

    folder_card = _card(
        ft.Column(
            [
                _label("PASTA PARA VERIFICAR"),
                ft.Row(
                    [
                        dir_txt,
                        ft.IconButton(
                            ft.Icons.FOLDER_OPEN_ROUNDED,
                            icon_color=ACCENT,
                            tooltip="Selecionar pasta",
                            on_click=lambda: _pick_directory(),
                        ),
                    ],
                    spacing=4,
                ),
            ],
            spacing=8, tight=True,
        )
    )

    metrics_row = ft.Row(
        [
            ft.Container(
                _card(ft.Column([val_analisados, _label("ANALISADOS")], spacing=4, tight=True)),
                expand=True,
            ),
            ft.Container(
                _card(ft.Column([val_suspeitos, _label("SUSPEITOS")], spacing=4, tight=True)),
                expand=True,
            ),
        ],
        spacing=12,
    )

    progress_card = _card(
        ft.Column(
            [
                ft.Row(
                    [progress_ring, status_txt],
                    spacing=10,
                    vertical_alignment=ft.CrossAxisAlignment.CENTER,
                ),
                ft.Row([progress_bar], expand=False),
                progress_lbl,
            ],
            spacing=6, tight=True,
        )
    )

    buttons_col = ft.Column(
        [
            ft.Row([scan_btn, full_scan_btn], spacing=8),
            ft.Row([stop_btn], alignment=ft.MainAxisAlignment.CENTER),
        ],
        spacing=8, tight=True,
    )

    body = ft.Column(
        [
            ft.Container(height=12),
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
            [header, body],
            spacing=0,
            expand=True,
        )
    )


if __name__ == "__main__":
    ft.app(target=main)
