"""Ponto de entrada da aplicacao SentinelaPC."""

from __future__ import annotations

import ctypes
import socket
import sys

from PySide6.QtGui import QIcon
from PySide6.QtWidgets import QApplication

from app.core.bootstrap import bootstrap_application
from app.ui.main_window import MainWindow
from app.ui.styles import build_stylesheet


_INSTANCE_LOCK_SOCKET: socket.socket | None = None


def _acquire_single_instance_lock() -> bool:
    """Impede multiplas instancias simultaneas do app no mesmo usuario."""
    global _INSTANCE_LOCK_SOCKET

    lock_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
        lock_socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)

    try:
        lock_socket.bind(("127.0.0.1", 54621))
        lock_socket.listen(1)
    except OSError:
        lock_socket.close()
        return False

    _INSTANCE_LOCK_SOCKET = lock_socket
    return True


def _show_already_running_message() -> None:
    """Mostra feedback claro quando o usuario tenta abrir uma segunda instancia."""
    message = "O SentinelaPC ja esta em execucao."
    if sys.platform.startswith("win"):
        ctypes.windll.user32.MessageBoxW(0, message, "SentinelaPC", 0x00000040)
        return
    print(message)


def main() -> int:
    """Inicializa a infraestrutura basica e abre a interface principal."""
    if not _acquire_single_instance_lock():
        _show_already_running_message()
        return 0

    context = bootstrap_application()

    app = QApplication(sys.argv)
    app.setApplicationName("SentinelaPC")
    app.setOrganizationName("SentinelaPC")
    app_font = app.font()
    app_font.setFamily("Segoe UI Variable Text")
    app_font.setPointSize(10)
    app.setFont(app_font)
    app.setStyleSheet(build_stylesheet())

    branding_dir = context.paths.resource_dir / "app" / "assets" / "branding"
    icon_candidates = [
        branding_dir / "sentinelapc.png",
        branding_dir / "logo-app-256.png",
    ]
    app_icon_path = next((path for path in icon_candidates if path.exists()), None)
    if app_icon_path is not None:
        icon = QIcon(str(app_icon_path))
        app.setWindowIcon(icon)

    window = MainWindow(context)
    if app_icon_path is not None:
        window.setWindowIcon(QIcon(str(app_icon_path)))
    window.show()

    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
