"""Icones lineares desenhados em Qt para a interface principal."""

from __future__ import annotations

from enum import Enum

from PySide6.QtCore import QPointF, QRectF, Qt
from PySide6.QtGui import QColor, QIcon, QPainter, QPainterPath, QPen, QPixmap


class Icons(Enum):
    """Enumeracao semantica dos icones usados pela UI."""

    DASHBOARD = "dashboard"
    FILES = "files"
    PROCESSES = "processes"
    STARTUP = "startup"
    BROWSERS = "browsers"
    EMAILS = "emails"
    AUDIT = "audit"
    QUARANTINE = "quarantine"
    REPORTS = "reports"
    HISTORY = "history"
    DIAGNOSTICS = "diagnostics"
    QUICK_SCAN = "quick_scan"
    FULL_SCAN = "full_scan"
    PAUSE = "pause"
    STOP = "stop"
    CHECK = "check"
    WARNING = "warning"
    ERROR = "error"
    FOLDER = "folder"
    DOWNLOAD = "download"
    SETTINGS = "settings"


def _draw_dashboard(painter: QPainter, rect: QRectF) -> None:
    painter.drawRoundedRect(rect.adjusted(2, 2, -2, -2), 7, 7)
    half_w = rect.width() / 2
    half_h = rect.height() / 2
    gap = 4
    cells = [
        QRectF(rect.left() + 6, rect.top() + 6, half_w - 10, half_h - 10),
        QRectF(rect.left() + half_w + gap / 2, rect.top() + 6, half_w - 10, half_h - 10),
        QRectF(rect.left() + 6, rect.top() + half_h + gap / 2, half_w - 10, half_h - 10),
        QRectF(rect.left() + half_w + gap / 2, rect.top() + half_h + gap / 2, half_w - 10, half_h - 10),
    ]
    for cell in cells:
        painter.drawRoundedRect(cell, 4, 4)


def _draw_document(painter: QPainter, rect: QRectF) -> None:
    doc = rect.adjusted(7, 4, -7, -4)
    fold = 8
    path = QPainterPath()
    path.moveTo(doc.left(), doc.top())
    path.lineTo(doc.right() - fold, doc.top())
    path.lineTo(doc.right(), doc.top() + fold)
    path.lineTo(doc.right(), doc.bottom())
    path.lineTo(doc.left(), doc.bottom())
    path.closeSubpath()
    painter.drawPath(path)
    painter.drawLine(QPointF(doc.right() - fold, doc.top()), QPointF(doc.right() - fold, doc.top() + fold))
    painter.drawLine(QPointF(doc.right() - fold, doc.top() + fold), QPointF(doc.right(), doc.top() + fold))
    for offset in (0.40, 0.58, 0.76):
        y = doc.top() + doc.height() * offset
        painter.drawLine(QPointF(doc.left() + 5, y), QPointF(doc.right() - 6, y))


def _draw_magnify(painter: QPainter, rect: QRectF) -> None:
    circle = QRectF(rect.left() + 6, rect.top() + 6, rect.width() * 0.48, rect.height() * 0.48)
    painter.drawEllipse(circle)
    painter.drawLine(QPointF(circle.right() - 1, circle.bottom() - 1), QPointF(rect.right() - 6, rect.bottom() - 6))


def _draw_file_search(painter: QPainter, rect: QRectF) -> None:
    _draw_document(painter, QRectF(rect.left(), rect.top(), rect.width() * 0.74, rect.height()))
    _draw_magnify(painter, QRectF(rect.left() + rect.width() * 0.30, rect.top() + rect.height() * 0.28, rect.width() * 0.70, rect.height() * 0.70))


def _draw_chip(painter: QPainter, rect: QRectF) -> None:
    body = rect.adjusted(8, 8, -8, -8)
    painter.drawRoundedRect(body, 6, 6)
    inner = body.adjusted(6, 6, -6, -6)
    painter.drawRoundedRect(inner, 3, 3)
    for idx in range(4):
        x = body.left() + (idx + 0.7) * body.width() / 4.6
        painter.drawLine(QPointF(x, rect.top() + 2), QPointF(x, body.top()))
        painter.drawLine(QPointF(x, body.bottom()), QPointF(x, rect.bottom() - 2))
    for idx in range(3):
        y = body.top() + (idx + 1) * body.height() / 4
        painter.drawLine(QPointF(rect.left() + 2, y), QPointF(body.left(), y))
        painter.drawLine(QPointF(body.right(), y), QPointF(rect.right() - 2, y))


def _draw_rocket(painter: QPainter, rect: QRectF) -> None:
    path = QPainterPath()
    path.moveTo(rect.center().x(), rect.top() + 4)
    path.quadTo(rect.right() - 5, rect.center().y(), rect.center().x(), rect.bottom() - 8)
    path.quadTo(rect.left() + 5, rect.center().y(), rect.center().x(), rect.top() + 4)
    painter.drawPath(path)
    painter.drawEllipse(QRectF(rect.center().x() - 4, rect.center().y() - 6, 8, 8))
    painter.drawLine(QPointF(rect.center().x() - 8, rect.bottom() - 11), QPointF(rect.center().x() - 2, rect.bottom() - 4))
    painter.drawLine(QPointF(rect.center().x() + 8, rect.bottom() - 11), QPointF(rect.center().x() + 2, rect.bottom() - 4))
    painter.drawLine(QPointF(rect.center().x(), rect.bottom() - 8), QPointF(rect.center().x(), rect.bottom() - 2))


def _draw_globe(painter: QPainter, rect: QRectF) -> None:
    circle = rect.adjusted(4, 4, -4, -4)
    painter.drawEllipse(circle)
    painter.drawLine(QPointF(circle.center().x(), circle.top()), QPointF(circle.center().x(), circle.bottom()))
    painter.drawArc(circle.adjusted(circle.width() * 0.18, 0, -circle.width() * 0.18, 0), 0, 5760)
    painter.drawArc(circle.adjusted(0, circle.height() * 0.22, 0, -circle.height() * 0.22), 0, 2880)
    painter.drawArc(circle.adjusted(0, circle.height() * 0.22, 0, -circle.height() * 0.22), 2880, 2880)


def _draw_envelope(painter: QPainter, rect: QRectF) -> None:
    box = rect.adjusted(4, 8, -4, -8)
    painter.drawRoundedRect(box, 4, 4)
    painter.drawLine(QPointF(box.left(), box.top()), QPointF(box.center().x(), box.center().y()))
    painter.drawLine(QPointF(box.right(), box.top()), QPointF(box.center().x(), box.center().y()))


def _draw_shield(painter: QPainter, rect: QRectF) -> None:
    path = QPainterPath()
    path.moveTo(rect.center().x(), rect.top() + 4)
    path.lineTo(rect.right() - 6, rect.top() + 10)
    path.lineTo(rect.right() - 9, rect.center().y() + 8)
    path.lineTo(rect.center().x(), rect.bottom() - 4)
    path.lineTo(rect.left() + 9, rect.center().y() + 8)
    path.lineTo(rect.left() + 6, rect.top() + 10)
    path.closeSubpath()
    painter.drawPath(path)
    painter.drawLine(QPointF(rect.center().x() - 7, rect.center().y()), QPointF(rect.center().x() - 1, rect.center().y() + 6))
    painter.drawLine(QPointF(rect.center().x() - 1, rect.center().y() + 6), QPointF(rect.center().x() + 8, rect.center().y() - 5))


def _draw_lock(painter: QPainter, rect: QRectF) -> None:
    body = QRectF(rect.left() + 7, rect.center().y() - 1, rect.width() - 14, rect.height() - 12)
    painter.drawRoundedRect(body, 5, 5)
    painter.drawArc(QRectF(rect.left() + 10, rect.top() + 4, rect.width() - 20, rect.height() * 0.50), 0, 2880)


def _draw_history(painter: QPainter, rect: QRectF) -> None:
    arc_rect = rect.adjusted(5, 5, -5, -5)
    painter.drawArc(arc_rect, 40 * 16, 275 * 16)
    painter.drawLine(QPointF(rect.left() + 6, rect.center().y() - 5), QPointF(rect.left() + 6, rect.center().y() + 5))
    painter.drawLine(QPointF(rect.left() + 6, rect.center().y() - 5), QPointF(rect.left() + 12, rect.center().y() - 1))
    painter.drawLine(QPointF(rect.center().x(), rect.center().y()), QPointF(rect.center().x(), rect.top() + 10))
    painter.drawLine(QPointF(rect.center().x(), rect.center().y()), QPointF(rect.center().x() + 8, rect.center().y() + 5))


def _draw_wrench(painter: QPainter, rect: QRectF) -> None:
    painter.drawArc(QRectF(rect.left() + 4, rect.top() + 4, 14, 14), 50 * 16, 240 * 16)
    painter.drawLine(QPointF(rect.left() + 15, rect.top() + 15), QPointF(rect.right() - 7, rect.bottom() - 7))
    painter.drawEllipse(QRectF(rect.right() - 11, rect.bottom() - 11, 8, 8))


def _draw_lightning(painter: QPainter, rect: QRectF) -> None:
    path = QPainterPath()
    path.moveTo(rect.center().x() + 2, rect.top() + 4)
    path.lineTo(rect.left() + 11, rect.center().y() + 1)
    path.lineTo(rect.center().x() + 1, rect.center().y() + 1)
    path.lineTo(rect.center().x() - 2, rect.bottom() - 4)
    path.lineTo(rect.right() - 10, rect.center().y() - 1)
    path.lineTo(rect.center().x() + 6, rect.center().y() - 1)
    path.closeSubpath()
    painter.drawPath(path)


def _draw_circle_control(painter: QPainter, rect: QRectF, mode: str) -> None:
    circle = rect.adjusted(4, 4, -4, -4)
    painter.drawEllipse(circle)
    if mode == "pause":
        painter.drawLine(QPointF(circle.center().x() - 4, circle.top() + 7), QPointF(circle.center().x() - 4, circle.bottom() - 7))
        painter.drawLine(QPointF(circle.center().x() + 4, circle.top() + 7), QPointF(circle.center().x() + 4, circle.bottom() - 7))
    elif mode == "stop":
        painter.drawRect(QRectF(circle.center().x() - 5, circle.center().y() - 5, 10, 10))
    elif mode == "alert":
        painter.drawLine(QPointF(circle.center().x(), circle.top() + 7), QPointF(circle.center().x(), circle.bottom() - 11))
        painter.drawPoint(QPointF(circle.center().x(), circle.bottom() - 6))
    elif mode == "check":
        painter.drawLine(QPointF(circle.center().x() - 7, circle.center().y()), QPointF(circle.center().x() - 1, circle.center().y() + 6))
        painter.drawLine(QPointF(circle.center().x() - 1, circle.center().y() + 6), QPointF(circle.center().x() + 8, circle.center().y() - 5))
    elif mode == "error":
        painter.drawLine(QPointF(circle.center().x() - 6, circle.center().y() - 6), QPointF(circle.center().x() + 6, circle.center().y() + 6))
        painter.drawLine(QPointF(circle.center().x() + 6, circle.center().y() - 6), QPointF(circle.center().x() - 6, circle.center().y() + 6))
    elif mode == "help":
        painter.drawArc(QRectF(circle.center().x() - 7, circle.top() + 6, 14, 12), 20 * 16, 220 * 16)
        painter.drawLine(QPointF(circle.center().x(), circle.center().y()), QPointF(circle.center().x(), circle.center().y() + 5))
        painter.drawPoint(QPointF(circle.center().x(), circle.bottom() - 6))


def _draw_folder(painter: QPainter, rect: QRectF) -> None:
    path = QPainterPath()
    path.moveTo(rect.left() + 5, rect.top() + 12)
    path.lineTo(rect.left() + 13, rect.top() + 12)
    path.lineTo(rect.left() + 17, rect.top() + 8)
    path.lineTo(rect.right() - 5, rect.top() + 8)
    path.lineTo(rect.right() - 5, rect.bottom() - 7)
    path.lineTo(rect.left() + 5, rect.bottom() - 7)
    path.closeSubpath()
    painter.drawPath(path)


def _draw_download(painter: QPainter, rect: QRectF) -> None:
    painter.drawLine(QPointF(rect.center().x(), rect.top() + 5), QPointF(rect.center().x(), rect.bottom() - 11))
    painter.drawLine(QPointF(rect.center().x() - 6, rect.bottom() - 17), QPointF(rect.center().x(), rect.bottom() - 11))
    painter.drawLine(QPointF(rect.center().x() + 6, rect.bottom() - 17), QPointF(rect.center().x(), rect.bottom() - 11))
    painter.drawLine(QPointF(rect.left() + 7, rect.bottom() - 6), QPointF(rect.right() - 7, rect.bottom() - 6))


def _draw_cloud_search(painter: QPainter, rect: QRectF) -> None:
    cloud = QPainterPath()
    cloud.moveTo(rect.left() + 8, rect.bottom() - 12)
    cloud.quadTo(rect.left() + 8, rect.center().y(), rect.left() + 16, rect.center().y())
    cloud.quadTo(rect.left() + 19, rect.top() + 8, rect.center().x(), rect.top() + 11)
    cloud.quadTo(rect.right() - 9, rect.top() + 10, rect.right() - 10, rect.center().y() + 2)
    cloud.quadTo(rect.right() - 4, rect.center().y() + 4, rect.right() - 6, rect.bottom() - 12)
    cloud.closeSubpath()
    painter.drawPath(cloud)
    _draw_magnify(painter, QRectF(rect.center().x() - 2, rect.center().y() + 1, 13, 13))


def _draw_logout(painter: QPainter, rect: QRectF) -> None:
    painter.drawRoundedRect(QRectF(rect.left() + 5, rect.top() + 5, rect.width() * 0.48, rect.height() - 10), 4, 4)
    painter.drawLine(QPointF(rect.center().x() - 1, rect.center().y()), QPointF(rect.right() - 6, rect.center().y()))
    painter.drawLine(QPointF(rect.right() - 12, rect.center().y() - 6), QPointF(rect.right() - 6, rect.center().y()))
    painter.drawLine(QPointF(rect.right() - 12, rect.center().y() + 6), QPointF(rect.right() - 6, rect.center().y()))


def _draw_icon(painter: QPainter, name: str, rect: QRectF) -> None:
    if name == "dashboard":
        _draw_dashboard(painter, rect)
    elif name == "files":
        _draw_file_search(painter, rect)
    elif name == "full_scan":
        _draw_magnify(painter, rect)
    elif name in {"processes", "process_scan"}:
        _draw_chip(painter, rect)
    elif name in {"startup", "startup_scan"}:
        _draw_rocket(painter, rect)
    elif name in {"browsers", "browser_scan"}:
        _draw_globe(painter, rect)
    elif name in {"emails", "email_scan_file", "email_connect_gmail", "email_connect_outlook", "email_scan_online", "email_set_manual_access"}:
        _draw_envelope(painter, rect)
    elif name in {"audit", "open_audit"}:
        _draw_shield(painter, rect)
    elif name in {"quarantine", "quarantine_file"}:
        _draw_lock(painter, rect)
    elif name in {"reports", "generate_report"}:
        _draw_document(painter, rect)
    elif name in {"history", "open_history"}:
        _draw_history(painter, rect)
    elif name in {"diagnostics", "pause_diagnostics", "stop_diagnostics"}:
        _draw_wrench(painter, rect)
    elif name == "quick_scan":
        _draw_lightning(painter, rect)
    elif name in {"pause", "pause_scan", "pause_process_scan", "pause_startup_scan", "pause_browser_scan", "pause_email_scan"}:
        _draw_circle_control(painter, rect, "pause")
    elif name in {"stop", "stop_scan", "stop_process_scan", "stop_startup_scan", "stop_browser_scan", "stop_email_scan"}:
        _draw_circle_control(painter, rect, "stop")
    elif name in {"check", "resolve_files", "resolve_processes", "resolve_startup", "resolve_browsers", "resolve_emails"}:
        _draw_circle_control(painter, rect, "check")
    elif name in {"warning", "browser_view_suspicious"}:
        _draw_circle_control(painter, rect, "alert")
    elif name == "browser_view_extensions":
        _draw_globe(painter, rect)
    elif name == "error":
        _draw_circle_control(painter, rect, "error")
    elif name in {"folder", "open_quarantine", "email_scan_folder"}:
        _draw_folder(painter, rect)
    elif name == "download":
        _draw_download(painter, rect)
    elif name in {"email_oauth_help", "help"}:
        _draw_circle_control(painter, rect, "help")
    elif name == "email_disconnect_account":
        _draw_logout(painter, rect)
    elif name == "cloud_search":
        _draw_cloud_search(painter, rect)
    else:
        _draw_document(painter, rect)


def get_icon(icon_name: str | tuple[str, ...], size: int = 24, color: str = "#f7fbff") -> QIcon | None:
    """Retorna um icone linear desenhado via QPainter."""
    semantic_name = icon_name[0] if isinstance(icon_name, tuple) else icon_name
    pixmap = QPixmap(size, size)
    pixmap.fill(Qt.GlobalColor.transparent)

    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    pen = QPen(QColor(color))
    pen.setWidthF(max(1.6, size * 0.08))
    pen.setCapStyle(Qt.PenCapStyle.RoundCap)
    pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
    painter.setPen(pen)
    painter.setBrush(Qt.BrushStyle.NoBrush)
    _draw_icon(painter, semantic_name, QRectF(1, 1, size - 2, size - 2))
    painter.end()
    return QIcon(pixmap)


ICON_MAP = {
    "dashboard": "dashboard",
    "files": "files",
    "processes": "processes",
    "startup": "startup",
    "browsers": "browsers",
    "emails": "emails",
    "audit": "audit",
    "quarantine": "quarantine",
    "reports": "reports",
    "history": "history",
    "diagnostics": "diagnostics",
    "quick_scan": "quick_scan",
    "full_scan": "full_scan",
    "resolve_files": "resolve_files",
    "resolve_processes": "resolve_processes",
    "resolve_startup": "resolve_startup",
    "resolve_browsers": "resolve_browsers",
    "resolve_emails": "resolve_emails",
    "pause_scan": "pause_scan",
    "stop_scan": "stop_scan",
    "process_scan": "process_scan",
    "startup_scan": "startup_scan",
    "open_audit": "open_audit",
    "open_history": "open_history",
    "quarantine_file": "quarantine_file",
    "open_quarantine": "open_quarantine",
    "generate_report": "generate_report",
    "browser_scan": "browser_scan",
    "browser_view_extensions": "browser_view_extensions",
    "browser_view_suspicious": "browser_view_suspicious",
    "email_scan_file": "email_scan_file",
    "email_scan_folder": "email_scan_folder",
    "email_set_manual_access": "email_set_manual_access",
    "email_oauth_help": "email_oauth_help",
    "email_connect_gmail": "email_connect_gmail",
    "email_connect_outlook": "email_connect_outlook",
    "email_scan_online": "email_scan_online",
    "email_disconnect_account": "email_disconnect_account",
    "pause_process_scan": "pause_process_scan",
    "stop_process_scan": "stop_process_scan",
    "pause_startup_scan": "pause_startup_scan",
    "stop_startup_scan": "stop_startup_scan",
    "pause_browser_scan": "pause_browser_scan",
    "stop_browser_scan": "stop_browser_scan",
    "pause_email_scan": "pause_email_scan",
    "stop_email_scan": "stop_email_scan",
    "pause_diagnostics": "pause_diagnostics",
    "stop_diagnostics": "stop_diagnostics",
    "open_dashboard": "dashboard",
}
