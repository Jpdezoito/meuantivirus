"""Ponto de entrada da aplicacao SentinelaPC."""

from __future__ import annotations

import sys

from PySide6.QtWidgets import QApplication

from app.core.bootstrap import bootstrap_application
from app.ui.main_window import MainWindow
from app.ui.styles import build_stylesheet


def main() -> int:
    """Inicializa a infraestrutura basica e abre a interface principal."""
    context = bootstrap_application()

    app = QApplication(sys.argv)
    app.setApplicationName("SentinelaPC")
    app.setOrganizationName("SentinelaPC")
    app_font = app.font()
    app_font.setFamily("Segoe UI")
    app_font.setPointSize(10)
    app.setFont(app_font)
    app.setStyleSheet(build_stylesheet())

    window = MainWindow(context)
    window.show()

    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
