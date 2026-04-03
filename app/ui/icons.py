"""Resource manager para ícones Font Awesome — UI Premium."""

from enum import Enum

try:
    from qtawesome import icon
    HAS_QTAWESOME = True
except ImportError:
    HAS_QTAWESOME = False


class Icons(Enum):
    """Enumeração de ícones Material Design Icons via qtawesome."""
    # Sidebar
    DASHBOARD = "mdi.view-dashboard"
    FILES = "mdi.file-search"
    PROCESSES = "mdi.cpu-64-bit"
    STARTUP = "mdi.rocket-launch"
    BROWSERS = "mdi.globe-model"
    EMAILS = "mdi.email"
    AUDIT = "mdi.shield-check"
    QUARANTINE = "mdi.lock"
    REPORTS = "mdi.file-document"
    HISTORY = "mdi.history"
    DIAGNOSTICS = "mdi.wrench"
    
    # Actions
    QUICK_SCAN = "mdi.lightning-bolt"
    FULL_SCAN = "mdi.magnify"
    PAUSE = "mdi.pause-circle"
    STOP = "mdi.stop-circle"
    
    # Status
    CHECK = "mdi.check-circle"
    WARNING = "mdi.alert-circle"
    ERROR = "mdi.close-circle"
    
    # Generic
    FOLDER = "mdi.folder-open"
    DOWNLOAD = "mdi.download"
    SETTINGS = "mdi.cog"


def get_icon(icon_name: str, size: int = 24, color: str = "#3b9eff"):
    """Retorna QIcon do Font Awesome. Se falhar, retorna None."""
    if not HAS_QTAWESOME:
        return None
    try:
        return icon(icon_name, color=color, scale_factor=1.0)
    except Exception:
        return None


# Mapeamento simples por página/ação
ICON_MAP = {
    "dashboard": "mdi.view-dashboard",
    "files": "mdi.file-search",
    "processes": "mdi.cpu-64-bit",
    "startup": "mdi.rocket-launch",
    "browsers": "mdi.globe-model",
    "emails": "mdi.email",
    "audit": "mdi.shield-check",
    "quarantine": "mdi.lock",
    "reports": "mdi.file-document",
    "history": "mdi.history",
    "diagnostics": "mdi.wrench",
    "quick_scan": "mdi.lightning-bolt",
    "full_scan": "mdi.magnify",
    "pause_scan": "mdi.pause-circle",
    "stop_scan": "mdi.stop-circle",
    "process_scan": "mdi.cpu-64-bit",
    "startup_scan": "mdi.rocket-launch",
    "open_audit": "mdi.shield-check",
    "open_history": "mdi.history",
    "quarantine_file": "mdi.lock",
    "diagnostics": "mdi.wrench",
    "open_quarantine": "mdi.folder-open",
    "generate_report": "mdi.file-document",
    "browser_scan": "mdi.globe-model",
    "browser_view_suspicious": "mdi.alert-circle",
    "email_scan_file": "mdi.email",
    "email_scan_folder": "mdi.folder-open",
    "email_oauth_help": "mdi.help-circle",
    "email_connect_gmail": "mdi.email",
    "email_connect_outlook": "mdi.email",
    "email_scan_online": "mdi.cloud-search",
    "email_disconnect_account": "mdi.logout",
    "pause_process_scan": "mdi.pause-circle",
    "stop_process_scan": "mdi.stop-circle",
    "pause_startup_scan": "mdi.pause-circle",
    "stop_startup_scan": "mdi.stop-circle",
    "pause_browser_scan": "mdi.pause-circle",
    "stop_browser_scan": "mdi.stop-circle",
    "pause_email_scan": "mdi.pause-circle",
    "stop_email_scan": "mdi.stop-circle",
    "pause_diagnostics": "mdi.pause-circle",
    "stop_diagnostics": "mdi.stop-circle",
    "open_dashboard": "mdi.view-dashboard",
}
