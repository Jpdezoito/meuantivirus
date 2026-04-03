"""Estilos centralizados da interface do SentinelaPC."""

from __future__ import annotations

# Paleta principal (dark modern)
# Fundo base:      #111827  (cinza-azul escuro — quase preto)
# Superfice card:  #1e2d3d  (azul-chumbo)
# Surface elevated:#253447  (destaque de card)
# Sidebar:         #0d1b2a  (quase preto frio)
# Accent:          #3b9eff  (azul claro vibrante)
# Accent hover:    #1a83f5
# Verde status:    #22c55e
# Vermelho alerta: #ef4444
# Texto primario:  #f0f6ff
# Texto secundario:#8ba3bb
# Border sutil:    #2a3f55


def build_stylesheet() -> str:
    """Retorna a folha de estilos global usada pela aplicacao."""
    return """
    /* ── Base global ─────────────────────────────────────── */
    QWidget {
        background-color: #111827;
        color: #f0f6ff;
        font-family: "Segoe UI";
        font-size: 12px;
    }

    QMainWindow {
        background-color: #111827;
    }

    QScrollBar:vertical {
        background: #111827;
        width: 6px;
        margin: 0px;
    }
    QScrollBar::handle:vertical {
        background: #2a3f55;
        border-radius: 3px;
        min-height: 30px;
    }
    QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
        height: 0px;
    }
    QScrollBar:horizontal {
        background: #111827;
        height: 6px;
        margin: 0px;
    }
    QScrollBar::handle:horizontal {
        background: #2a3f55;
        border-radius: 3px;
        min-width: 30px;
    }
    QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
        width: 0px;
    }

    /* ── Header superior ─────────────────────────────────── */
    QFrame#topHeader {
        background-color: #0d1b2a;
        border-bottom: 1px solid #1e2d3d;
    }

    QLabel#appTitle {
        font-size: 20px;
        font-weight: 700;
        color: #f0f6ff;
        letter-spacing: -0.3px;
    }

    QLabel#appSubtitle {
        font-size: 11px;
        color: #8ba3bb;
    }

    /* ── Sidebar ────────────────────────────────────────────── */
    QWidget#navSidebar {
        background-color: #0d1b2a;
        border-right: 2px solid #1e3f5c;
    }

    QLabel#navBrand {
        color: #f0f6ff;
        font-size: 20px;
        font-weight: 800;
        letter-spacing: -0.5px;
    }

    QLabel#navSubtitle {
        color: #5d7a93;
        font-size: 10px;
        font-weight: 500;
    }

    QLabel#navFooter {
        color: #374f63;
        font-size: 10px;
        font-weight: 500;
    }

    QLabel#navSectionLabel {
        color: #3b6480;
        font-size: 10px;
        font-weight: 800;
        letter-spacing: 1.5px;
    }

    QPushButton#navButton {
        background-color: transparent;
        color: #8ba3bb;
        border: none;
        border-radius: 12px;
        padding: 14px 16px;
        min-height: 44px;
        margin: 0px 8px;
        text-align: left;
        font-size: 13px;
        font-weight: 600;
        icon-size: 32px;
    }

    QPushButton#navButton:hover {
        background-color: #1a3f5e;
        color: #cde2f5;
        border-left: 3px solid transparent;
        padding-left: 13px;
    }

    QPushButton#navButton:checked {
        background-color: #1a4570;
        color: #3b9eff;
        font-weight: 700;
        border-left: 4px solid #3b9eff;
        padding-left: 12px;
        box-shadow: inset -2px 0 8px rgba(59, 158, 255, 0.2);
    }

    /* ── Cards ──────────────────────────────────────────────── */
    QFrame#cardFrame {
        background-color: #1e2d3d;
        border: 1px solid #2a3f55;
        border-radius: 16px;
        box-shadow: 0 2px 8px rgba(0, 0, 0, 0.3);
    }

    QFrame#cardFrameElevated {
        background-color: #253447;
        border: 1px solid #334d66;
        border-radius: 16px;
        box-shadow: 0 4px 16px rgba(0, 0, 0, 0.5);
    }

    QFrame#heroCard {
        background: qlineargradient(
            x1:0, y1:0, x2:1, y2:1,
            stop:0 #1d3d56,
            stop:0.5 #192f46,
            stop:1 #1d3f56
        );
        border: 2px solid #2e4a66;
        border-radius: 20px;
        box-shadow: 0 8px 20px rgba(59, 158, 255, 0.2);
    }

    /* ── Tipografia de pagina ──────────────────────────────── */
    QLabel#pageEyebrow {
        color: #3b9eff;
        font-size: 11px;
        font-weight: 800;
        letter-spacing: 2px;
    }

    QLabel#pageTitleLarge {
        color: #f0f6ff;
        font-size: 32px;
        font-weight: 800;
        letter-spacing: -0.5px;
    }

    QLabel#pageSubtitle {
        color: #6e8ea6;
        font-size: 13px;
        font-weight: 500;
    }

    QLabel#sectionTitle {
        font-size: 15px;
        font-weight: 700;
        color: #cde2f5;
        letter-spacing: 0.2px;
    }

    QLabel#sectionDescription {
        font-size: 11px;
        color: #5d7a93;
        font-weight: 500;
        line-height: 1.4;
    }

    /* ── Hero status (Dashboard) ─────────────────────────── */
    QLabel#heroStatusTitle {
        font-size: 22px;
        font-weight: 700;
        color: #22c55e;
    }

    QLabel#heroStatusSubtitle {
        font-size: 12px;
        color: #7aab8c;
    }

    QLabel#heroStatusTitleWarn {
        font-size: 22px;
        font-weight: 700;
        color: #f59e0b;
    }

    QLabel#heroStatusTitleDanger {
        font-size: 22px;
        font-weight: 700;
        color: #ef4444;
    }

    /* ── Metrics ────────────────────────────────────────────── */
    QLabel#metricLabel {
        font-size: 11px;
        font-weight: 600;
        color: #5d7a93;
        letter-spacing: 1px;
    }

    QLabel#metricValue {
        font-size: 32px;
        font-weight: 800;
        color: #3b9eff;
        letter-spacing: 0.5px;
    }

    QLabel#metricCaption {
        font-size: 10px;
        color: #4d6a83;
        line-height: 1.4;
    }

    QLabel#progressPercentLabel {
        font-size: 20px;
        font-weight: 800;
        color: #35d0ff;
        letter-spacing: 0.5px;
    }

    QProgressBar#scanProgressBar {
        border: 1px solid #2d4259;
        border-radius: 10px;
        background-color: #0f1c28;
        min-height: 14px;
        max-height: 14px;
    }

    QProgressBar#scanProgressBar::chunk {
        border-radius: 8px;
        background: qlineargradient(
            x1:0, y1:0, x2:1, y2:0,
            stop:0 #1de4ff,
            stop:0.55 #3b9eff,
            stop:1 #7dff4d
        );
    }

    /* ── Action tile buttons (dashboard grid) ───────────────── */
    QPushButton#actionTile {
        background-color: #1a2f40;
        color: #c8dff0;
        border: 1px solid #2d4564;
        border-radius: 16px;
        padding: 18px 14px;
        font-size: 12px;
        font-weight: 600;
        text-align: center;
        icon-size: 48px;
        box-shadow: 0 2px 8px rgba(0, 0, 0, 0.4);
    }

    QPushButton#actionTile:hover {
        background-color: #1d3f56;
        border-color: #3b9eff;
        color: #f0f6ff;
        box-shadow: 0 4px 12px rgba(59, 158, 255, 0.25);
    }

    QPushButton#actionTile:pressed {
        background-color: #16293c;
        border-color: #3b9eff;
        box-shadow: inset 0 2px 6px rgba(0, 0, 0, 0.6);
    }

    QPushButton#actionTile:disabled {
        background-color: #161f2b;
        color: #2d4259;
        border-color: #1e2f3e;
    }

    /* ── Botoes de operacao (inline pages) ──────────────────── */
    QPushButton#primaryActionButton {
        background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                        stop:0 #2e8ee8, stop:1 #1a6dbf);
        color: #ffffff;
        border: none;
        border-radius: 12px;
        padding: 14px 22px;
        min-height: 52px;
        font-size: 13px;
        font-weight: 700;
        text-align: center;
        icon-size: 20px;
    }

    QPushButton#primaryActionButton:hover {
        background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                        stop:0 #3b9eff, stop:1 #2176ca);
        box-shadow: 0 6px 16px rgba(59, 158, 255, 0.3);
    }

    QPushButton#primaryActionButton:pressed {
        background: #1765b5;
        box-shadow: inset 0 2px 6px rgba(0, 0, 0, 0.6);
    }

    QPushButton#primaryActionButton:focus {
        outline: 2px solid #3b9eff;
        outline-offset: 2px;
    }

    QPushButton#primaryActionButton:disabled {
        background: #1e2d3d;
        color: #2d4259;
    }

    QPushButton#secondaryActionButton {
        background-color: #1a2c3e;
        color: #8ba3bb;
        border: 1px solid #2a3f55;
        border-radius: 12px;
        padding: 14px 22px;
        min-height: 52px;
        font-size: 13px;
        font-weight: 600;
        text-align: center;
        icon-size: 20px;
    }

    QPushButton#secondaryActionButton:hover {
        background-color: #1e3449;
        color: #c8dff0;
        border-color: #3b9eff;
        box-shadow: 0 4px 12px rgba(59, 158, 255, 0.15);
    }

    QPushButton#secondaryActionButton:pressed {
        background-color: #172940;
        box-shadow: inset 0 2px 6px rgba(0, 0, 0, 0.6);
    }

    QPushButton#secondaryActionButton:disabled {
        color: #2d4259;
        border-color: #1e2f3e;
    }

    QPushButton#dangerActionButton {
        background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                        stop:0 #d55252, stop:1 #b83a3a);
        color: #ffffff;
        border: none;
        border-radius: 10px;
        padding: 11px 20px;
        font-size: 12px;
        font-weight: 700;
        text-align: left;
    }

    QPushButton#dangerActionButton:hover {
        background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                        stop:0 #e26464, stop:1 #c94242);
    }

    QPushButton#dangerActionButton:pressed {
        background: #a53131;
    }

    QPushButton#dangerActionButton:disabled {
        background: #3a2323;
        color: #7f8c98;
    }

    /* ── Consoles e texto ────────────────────────────────────── */
    QTextEdit#resultsConsole, QTextEdit#pageConsole {
        background: qlineargradient(
            x1:0, y1:0, x2:0, y2:1,
            stop:0 #0d1520,
            stop:1 #0f1c28
        );
        color: #65d0ff;
        border: 1px solid #1e3f5c;
        border-radius: 12px;
        padding: 16px;
        font-family: "Consolas", "Monaco", "Courier New", monospace;
        font-size: 12px;
        selection-background-color: #1d4570;
        selection-color: #f0f6ff;
        box-shadow: inset 0 1px 4px rgba(0, 0, 0, 0.5);
    }

    QTextEdit#resultsConsole:focus, QTextEdit#pageConsole:focus {
        border: 1px solid #3b9eff;
    }

    /* ── Tabelas ─────────────────────────────────────────── */
    QTableWidget#dataTable {
        background-color: #161f2b;
        alternate-background-color: #1a2738;
        color: #c8dff0;
        border: 1px solid #2a3f55;
        border-radius: 14px;
        gridline-color: #1e2d3d;
        selection-background-color: #1d3f5c;
        selection-color: #f0f6ff;
    }

    QHeaderView::section {
        background-color: #1a2c3e;
        color: #5d7a93;
        border: none;
        border-bottom: 1px solid #2a3f55;
        padding: 10px 12px;
        font-size: 10px;
        font-weight: 700;
        letter-spacing: 0.8px;
    }

    QTableWidget::item {
        padding: 8px 12px;
        border: none;
    }

    QTableWidget::item:selected {
        background-color: #1d3f5c;
        color: #f0f6ff;
    }

    /* ── ComboBox ────────────────────────────────────────── */
    QComboBox {
        background-color: #1e2d3d;
        color: #c8dff0;
        border: 1px solid #2a3f55;
        border-radius: 8px;
        padding: 6px 12px;
        font-size: 12px;
    }

    QComboBox:hover {
        border-color: #3b9eff;
    }

    QComboBox QAbstractItemView {
        background-color: #1e2d3d;
        color: #c8dff0;
        border: 1px solid #2a3f55;
        selection-background-color: #1d3f5c;
        selection-color: #f0f6ff;
    }

    QComboBox::drop-down {
        border: none;
        width: 20px;
    }

    /* ── Barra de status ─────────────────────────────────── */
    QStatusBar {
        background-color: #0d1b2a;
        color: #4a6680;
        border-top: 1px solid #1a2c3e;
        font-size: 11px;
    }

    /* ── MessageBox e dialogs ────────────────────────────── */
    QMessageBox {
        background-color: #1e2d3d;
        color: #f0f6ff;
    }

    QMessageBox QPushButton {
        background-color: #253447;
        color: #c8dff0;
        border: 1px solid #2a3f55;
        border-radius: 8px;
        padding: 8px 20px;
        font-weight: 600;
        min-width: 80px;
    }

    QMessageBox QPushButton:hover {
        background-color: #1d3f5c;
        border-color: #3b9eff;
        color: #f0f6ff;
    }

    QMessageBox QLabel {
        color: #c8dff0;
        background-color: transparent;
    }

    QDialog#confirmActionDialog,
    QDialog#adminPermissionDialog {
        background-color: #111827;
        color: #f0f6ff;
    }

    QLabel#dialogTitle {
        font-size: 20px;
        font-weight: 700;
        color: #f0f6ff;
    }

    QLabel#dialogSeverityLabel {
        color: #35d0ff;
        font-size: 10px;
        font-weight: 700;
        letter-spacing: 1.2px;
        text-transform: uppercase;
    }

    QLabel#dialogBody {
        color: #c8dff0;
        font-size: 12px;
    }

    QLabel#dialogWarning {
        color: #ffcc7a;
        font-size: 11px;
        font-weight: 600;
    }

    QDialog QLineEdit {
        background-color: #0f1c28;
        color: #f0f6ff;
        border: 1px solid #2a3f55;
        border-radius: 8px;
        padding: 10px 12px;
    }

    QDialog QLineEdit:focus {
        border-color: #3b9eff;
    }

    /* ── Separadores e frames auxiliares ─────────────────── */
    QFrame[frameShape="4"],
    QFrame[frameShape="5"] {
        color: #1e2d3d;
        background-color: #1e2d3d;
    }

    QFrame#contentArea {
        background-color: transparent;
    }
    """
