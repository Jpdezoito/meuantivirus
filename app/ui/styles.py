"""Estilos centralizados da interface do SentinelaPC."""

from __future__ import annotations


def build_stylesheet() -> str:
    """Retorna a folha de estilos global usada pela aplicacao."""
    return """
    QWidget {
        background-color: #08111f;
        color: #eff6ff;
        font-family: "Segoe UI Variable Text", "Bahnschrift", "Segoe UI";
        font-size: 12px;
    }

    QLabel {
        background: transparent;
    }

    QMainWindow {
        background: qlineargradient(
            x1: 0, y1: 0, x2: 1, y2: 1,
            stop: 0 #050c16,
            stop: 0.55 #0a1220,
            stop: 1 #0d1830
        );
    }

    QWidget#appShell {
        background: qlineargradient(
            x1: 0, y1: 0, x2: 1, y2: 1,
            stop: 0 #07101d,
            stop: 0.48 #091526,
            stop: 1 #0d1b33
        );
    }

    QWidget#contentArea {
        background: transparent;
    }

    QScrollArea#shellScrollArea,
    QScrollArea#sidebarScrollArea,
    QScrollArea#pageScrollArea,
    QScrollArea#operationScrollArea,
    QScrollArea#auditScrollArea {
        background: transparent;
        border: none;
    }

    QScrollArea#shellScrollArea > QWidget > QWidget,
    QScrollArea#sidebarScrollArea > QWidget > QWidget,
    QScrollArea#pageScrollArea > QWidget > QWidget,
    QScrollArea#operationScrollArea > QWidget > QWidget,
    QScrollArea#auditScrollArea > QWidget > QWidget {
        background: transparent;
    }

    QWidget#pageSurface {
        background: qlineargradient(
            x1: 0, y1: 0, x2: 0, y2: 1,
            stop: 0 #0b1628,
            stop: 1 #0a1322
        );
        border: 1px solid #1b2d48;
        border-radius: 24px;
    }

    QStackedWidget {
        background: transparent;
    }

    QScrollBar:vertical {
        background: transparent;
        width: 8px;
        margin: 4px 0px 4px 0px;
    }

    QScrollBar::handle:vertical {
        background: #27425f;
        border-radius: 4px;
        min-height: 32px;
    }

    QScrollBar:horizontal {
        background: transparent;
        height: 8px;
        margin: 0px 4px 0px 4px;
    }

    QScrollBar::handle:horizontal {
        background: #27425f;
        border-radius: 4px;
        min-width: 32px;
    }

    QScrollBar::add-line:vertical,
    QScrollBar::sub-line:vertical,
    QScrollBar::add-line:horizontal,
    QScrollBar::sub-line:horizontal {
        width: 0px;
        height: 0px;
        border: none;
    }

    QWidget#topHeader {
        background: qlineargradient(
            x1: 0, y1: 0, x2: 1, y2: 0,
            stop: 0 #0d1a2d,
            stop: 1 #0f2138
        );
        border: 1px solid #1f3554;
        border-radius: 22px;
    }

    QLabel#appKicker {
        color: #67f0d3;
        font-size: 10px;
        font-weight: 700;
    }

    QLabel#appTitle {
        font-family: "Segoe UI Variable Display", "Bahnschrift", "Segoe UI";
        font-size: 28px;
        font-weight: 700;
        color: #f7fbff;
    }

    QLabel#appSubtitle {
        color: #90a7c4;
        font-size: 12px;
    }

    QWidget#headerMetaGroup {
        background: transparent;
    }

    QLabel#headerPill,
    QLabel#headerPillAccent {
        padding: 0 14px;
        min-height: 34px;
        border-radius: 14px;
        border: 1px solid #28405f;
        background: #0d1829;
        color: #d8e8ff;
        font-weight: 600;
    }

    QLabel#headerPillAccent {
        background: #103528;
        border-color: #1e745c;
        color: #82ffd8;
    }

    QLabel#headerPillWarn {
        padding: 0 14px;
        min-height: 34px;
        border-radius: 14px;
        border: 1px solid #6a4b1f;
        background: #2b1f0f;
        color: #ffd998;
        font-weight: 600;
    }

    QLabel#headerPillMuted {
        padding: 0 14px;
        min-height: 34px;
        border-radius: 14px;
        border: 1px solid #354c67;
        background: #1a2535;
        color: #b3c7dd;
        font-weight: 600;
    }

    QPushButton#realTimeProtectionToggleOn,
    QPushButton#realTimeProtectionToggleOff {
        padding: 0 14px;
        border-radius: 14px;
        font-weight: 700;
        min-height: 34px;
        text-align: center;
    }

    QPushButton#realTimeProtectionToggleOn {
        background: #103528;
        border: 1px solid #1e745c;
        color: #82ffd8;
    }

    QPushButton#realTimeProtectionToggleOn:hover {
        background: #134336;
        border-color: #249073;
    }

    QPushButton#realTimeProtectionToggleOn:pressed {
        background: #0d2d22;
    }

    QPushButton#realTimeProtectionToggleOff {
        background: #261f15;
        border: 1px solid #7b6234;
        color: #ffd8a1;
    }

    QPushButton#realTimeProtectionToggleOff:hover {
        background: #322718;
        border-color: #9a7b44;
    }

    QPushButton#realTimeProtectionToggleOff:pressed {
        background: #1d170f;
    }

    QWidget#navSidebar {
        background: qlineargradient(
            x1: 0, y1: 0, x2: 0, y2: 1,
            stop: 0 #0b1424,
            stop: 1 #0a1220
        );
        border: 1px solid #1a2d48;
        border-radius: 24px;
    }

    QLabel#navMonogram {
        min-width: 44px;
        max-width: 44px;
        min-height: 44px;
        max-height: 44px;
        border-radius: 22px;
        background: qlineargradient(
            x1: 0, y1: 0, x2: 1, y2: 1,
            stop: 0 #0fd1b4,
            stop: 1 #1875ff
        );
        color: #04111e;
        font-weight: 800;
        font-size: 15px;
    }

    QLabel#navLogoImage {
        min-width: 232px;
        max-width: 232px;
        min-height: 168px;
        max-height: 168px;
        border: none;
        background: transparent;
        padding: 0px;
    }

    QLabel#navOverline {
        color: #50d9c2;
        font-size: 10px;
        font-weight: 700;
    }

    QLabel#navBrand {
        color: #f7fbff;
        font-family: "Segoe UI Variable Display", "Bahnschrift", "Segoe UI";
        font-size: 20px;
        font-weight: 700;
    }

    QLabel#navSubtitle {
        color: #7f96b3;
        font-size: 10px;
    }

    QLabel#navSectionLabel {
        color: #4edcc3;
        font-size: 10px;
        font-weight: 700;
    }

    QPushButton#navButton {
        background: #0c1729;
        color: #a6bbd4;
        border: 1px solid transparent;
        border-radius: 16px;
        padding: 12px 14px;
        min-height: 48px;
        text-align: left;
        font-size: 12px;
        font-weight: 600;
    }

    QPushButton#navButton:hover {
        background: #12243c;
        color: #eff6ff;
        border-color: #264261;
    }

    QPushButton#navButton:checked {
        background: qlineargradient(
            x1: 0, y1: 0, x2: 1, y2: 0,
            stop: 0 #103251,
            stop: 1 #14395b
        );
        color: #6fded1;
        border: 1px solid #2a6b86;
        font-weight: 700;
    }

    QWidget#navFooterCard {
        background: #0d182a;
        border: 1px solid #223753;
        border-radius: 18px;
    }

    QLabel#navFooterTitle {
        color: #f4fbff;
        font-size: 13px;
        font-weight: 700;
    }

    QLabel#navFooter {
        color: #7f96b3;
        font-size: 11px;
    }

    QFrame#cardFrame,
    QFrame#featureCard,
    QFrame#toolbarCard,
    QFrame#dashboardLeadCard {
        background: #0d1829;
        border: 1px solid #1d314d;
        border-radius: 22px;
    }

    QFrame#cardFrameElevated {
        background: qlineargradient(
            x1: 0, y1: 0, x2: 0, y2: 1,
            stop: 0 #101d31,
            stop: 1 #0d1829
        );
        border: 1px solid #203554;
        border-radius: 22px;
    }

    QFrame#heroCard {
        background: qlineargradient(
            x1: 0, y1: 0, x2: 1, y2: 1,
            stop: 0 #0e3d45,
            stop: 0.48 #123556,
            stop: 1 #10223f
        );
        border: 1px solid #2a5a77;
        border-radius: 26px;
    }

    QLabel#pageEyebrow {
        color: #67f0d3;
        font-size: 10px;
        font-weight: 800;
    }

    QLabel#pageTitleLarge {
        color: #f7fbff;
        font-family: "Segoe UI Variable Display", "Bahnschrift", "Segoe UI";
        font-size: 30px;
        font-weight: 700;
    }

    QLabel#pageSubtitle {
        color: #95aaca;
        font-size: 13px;
    }

    QLabel#sectionTitle {
        font-size: 15px;
        font-weight: 700;
        color: #eff6ff;
    }

    QLabel#sectionDescription {
        color: #7f96b3;
        font-size: 11px;
    }

    QLabel#heroBadge {
        background: rgba(3, 16, 26, 0.3);
        border: 1px solid rgba(207, 247, 255, 0.22);
        border-radius: 28px;
        color: #f7fbff;
        font-size: 22px;
        font-weight: 800;
    }

    QLabel#heroStatusTitle,
    QLabel#heroStatusTitleWarn,
    QLabel#heroStatusTitleDanger {
        font-family: "Segoe UI Variable Display", "Bahnschrift", "Segoe UI";
        font-size: 25px;
        font-weight: 700;
    }

    QLabel#heroStatusTitle {
        color: #8effd7;
    }

    QLabel#heroStatusTitleWarn {
        color: #ffd26b;
    }

    QLabel#heroStatusTitleDanger {
        color: #ff8a8a;
    }

    QLabel#heroStatusSubtitle {
        color: #d2ecff;
        font-size: 13px;
    }

    QLabel#heroMetaLabel {
        color: #b8d8f7;
        font-size: 11px;
        font-weight: 700;
    }

    QWidget#heroMetaPanel {
        background: rgba(4, 17, 30, 0.28);
        border: 1px solid rgba(215, 241, 255, 0.14);
        border-radius: 18px;
    }

    QLabel#heroMetaValue {
        color: #edf8ff;
        font-size: 12px;
    }

    QLabel#metricIcon {
        background: #102840;
        border: 1px solid #274d70;
        border-radius: 17px;
        color: #72ebd3;
        font-weight: 700;
        font-size: 13px;
    }

    QLabel#metricLabel {
        font-size: 10px;
        font-weight: 700;
        color: #77c6c0;
    }

    QLabel#metricValue {
        font-family: "Segoe UI Variable Display", "Bahnschrift", "Segoe UI";
        font-size: 28px;
        font-weight: 700;
        color: #f7fbff;
    }

    QLabel#metricCaption {
        font-size: 11px;
        color: #7f96b3;
    }

    QLabel#progressPercentLabel {
        font-size: 20px;
        font-weight: 800;
        color: #67f0d3;
    }

    QProgressBar#scanProgressBar {
        border: 1px solid #28405f;
        border-radius: 10px;
        background-color: #08111f;
        min-height: 14px;
        max-height: 14px;
    }

    QProgressBar#scanProgressBar::chunk {
        border-radius: 8px;
        background: qlineargradient(
            x1: 0, y1: 0, x2: 1, y2: 0,
            stop: 0 #0fd1b4,
            stop: 0.55 #1e9fff,
            stop: 1 #8dff94
        );
    }

    QWidget#carouselStage {
        background: transparent;
    }

    QPushButton#actionTile,
    QPushButton#actionTileCenter {
        background: qlineargradient(
            x1: 0, y1: 0, x2: 0, y2: 1,
            stop: 0 #1e3a5a,
            stop: 1 #172f4a
        );
        color: #e8f4ff;
        border: 2px solid #2d5888;
        border-radius: 18px;
        padding: 10px 10px;
        font-size: 12px;
        font-weight: 700;
        text-align: center;
    }

    QPushButton#actionTileCenter {
        background: qlineargradient(
            x1: 0, y1: 0, x2: 1, y2: 1,
            stop: 0 #285178,
            stop: 0.55 #1f4469,
            stop: 1 #17324e
        );
        border: 2px solid #4db8db;
        color: #f4fbff;
        padding: 12px 12px;
        font-size: 13px;
    }

    QPushButton#actionTile:hover,
    QPushButton#actionTileCenter:hover {
        background: qlineargradient(
            x1: 0, y1: 0, x2: 0, y2: 1,
            stop: 0 #15304c,
            stop: 1 #11213a
        );
        border-color: #3aa8c7;
    }

    QPushButton#actionTileCenter:hover {
        background: qlineargradient(
            x1: 0, y1: 0, x2: 1, y2: 1,
            stop: 0 #316189,
            stop: 0.6 #224b73,
            stop: 1 #193754
        );
        border-color: #6ce6ea;
    }

    QPushButton#actionTile:pressed,
    QPushButton#actionTileCenter:pressed {
        background: #0c1728;
    }

    QPushButton#actionTile:disabled,
    QPushButton#actionTileCenter:disabled {
        background: #0b1320;
        color: #53667f;
        border-color: #172638;
    }

    QPushButton#actionTileSide {
        background: #0e1e30;
        color: #5a87aa;
        border: 1px solid #1c3550;
        border-radius: 18px;
        padding: 8px 8px;
        font-size: 11px;
        font-weight: 600;
        text-align: center;
    }

    QPushButton#actionTileSide:hover {
        background: #132840;
        border-color: #2a5070;
        color: #88b8d8;
    }

    QPushButton#actionTileSide:pressed {
        background: #0a1828;
    }

    QPushButton#actionTileSide:disabled {
        background: #090f1a;
        color: #3a4f66;
        border-color: #111e2e;
    }

    QLabel#carouselInfoLabel {
        color: #8fb0d3;
        font-size: 11px;
        font-weight: 700;
    }

    QPushButton#carouselArrowButton {
        min-width: 42px;
        max-width: 42px;
        min-height: 42px;
        max-height: 42px;
        border-radius: 21px;
        border: 1px solid #2b4b6f;
        background: #10243c;
        color: #d9ecff;
        font-size: 20px;
        font-weight: 700;
    }

    QPushButton#carouselArrowButton:hover {
        border-color: #3aa8c7;
        background: #14304d;
    }

    QPushButton#carouselArrowButton:pressed {
        background: #0d1e31;
    }

    QPushButton#primaryActionButton,
    QPushButton#secondaryActionButton,
    QPushButton#dangerActionButton {
        border-radius: 14px;
        padding: 14px 18px;
        font-size: 13px;
        font-weight: 700;
        text-align: left;
    }

    QPushButton#primaryActionButton {
        color: #05111e;
        background: qlineargradient(
            x1: 0, y1: 0, x2: 1, y2: 0,
            stop: 0 #68f0d4,
            stop: 1 #34a7ff
        );
        border: 1px solid #55c6d6;
    }

    QPushButton#primaryActionButton:hover {
        background: qlineargradient(
            x1: 0, y1: 0, x2: 1, y2: 0,
            stop: 0 #7ff5dc,
            stop: 1 #50b5ff
        );
    }

    QPushButton#primaryActionButton:pressed {
        background: #42b8d6;
    }

    QPushButton#primaryActionButton:disabled {
        background: #162739;
        color: #51657d;
        border-color: #1e2f43;
    }

    QPushButton#secondaryActionButton {
        background: #101b2d;
        color: #d5e7fb;
        border: 1px solid #26405f;
    }

    QPushButton#secondaryActionButton:hover {
        background: #14233a;
        border-color: #3aa8c7;
    }

    QPushButton#secondaryActionButton:pressed {
        background: #0d1728;
    }

    QPushButton#secondaryActionButton:disabled {
        background: #101824;
        color: #4f6279;
        border-color: #172638;
    }

    QPushButton#dangerActionButton {
        background: #4a1d26;
        color: #ffe7eb;
        border: 1px solid #8d3348;
    }

    QPushButton#dangerActionButton:hover {
        background: #612130;
    }

    QPushButton#dangerActionButton:pressed {
        background: #431723;
    }

    QTextEdit#resultsConsole,
    QTextEdit#pageConsole {
        background: qlineargradient(
            x1: 0, y1: 0, x2: 0, y2: 1,
            stop: 0 #08111e,
            stop: 1 #0b1624
        );
        color: #9ad9ff;
        border: 1px solid #20334e;
        border-radius: 16px;
        padding: 16px;
        font-family: "Cascadia Code", "Consolas", "Courier New";
        font-size: 12px;
        selection-background-color: #18456b;
        selection-color: #f7fbff;
    }

    QTextEdit#resultsConsole:focus,
    QTextEdit#pageConsole:focus {
        border: 1px solid #3aa8c7;
    }

    QTableWidget#dataTable {
        background-color: #0d1827;
        alternate-background-color: #112038;
        color: #d7e7f9;
        border: 1px solid #21344f;
        border-radius: 16px;
        gridline-color: #172536;
        selection-background-color: #163758;
        selection-color: #f7fbff;
    }

    QHeaderView::section {
        background-color: #101d31;
        color: #78c7c1;
        border: none;
        border-bottom: 1px solid #20324d;
        padding: 10px 12px;
        font-size: 10px;
        font-weight: 800;
    }

    QTableWidget::item {
        padding: 8px 12px;
        border: none;
    }

    QTableWidget::item:selected {
        background-color: #163758;
        color: #f7fbff;
    }

    QComboBox {
        background-color: #101d31;
        color: #d7e7f9;
        border: 1px solid #24405f;
        border-radius: 10px;
        padding: 8px 12px;
        min-height: 18px;
    }

    QComboBox:hover,
    QComboBox:focus {
        border-color: #3aa8c7;
    }

    QComboBox QAbstractItemView {
        background-color: #101d31;
        color: #d7e7f9;
        border: 1px solid #24405f;
        selection-background-color: #163758;
        selection-color: #f7fbff;
    }

    QComboBox::drop-down {
        border: none;
        width: 24px;
    }

    QStatusBar {
        background-color: #091220;
        color: #7b93b2;
        border-top: 1px solid #16273a;
        font-size: 11px;
    }

    QMessageBox {
        background-color: #0d1829;
        color: #f7fbff;
    }

    QMessageBox QPushButton {
        background-color: #101d31;
        color: #d7e7f9;
        border: 1px solid #26405f;
        border-radius: 10px;
        padding: 8px 20px;
        font-weight: 700;
        min-width: 84px;
    }

    QMessageBox QPushButton:hover {
        background-color: #15304c;
        border-color: #3aa8c7;
    }

    QMessageBox QLabel {
        color: #d7e7f9;
        background-color: transparent;
    }

    QDialog#confirmActionDialog,
    QDialog#adminPermissionDialog {
        background-color: #08111f;
        color: #f7fbff;
    }

    QLabel#dialogTitle {
        font-size: 20px;
        font-weight: 700;
        color: #f7fbff;
    }

    QLabel#dialogSeverityLabel {
        color: #67f0d3;
        font-size: 10px;
        font-weight: 700;
    }

    QLabel#dialogBody {
        color: #d7e7f9;
        font-size: 12px;
    }

    QLabel#dialogWarning {
        color: #ffd58c;
        font-size: 11px;
        font-weight: 700;
    }

    QDialog QLineEdit {
        background-color: #0a1422;
        color: #f7fbff;
        border: 1px solid #223753;
        border-radius: 10px;
        padding: 10px 12px;
    }

    QDialog QLineEdit:focus {
        border-color: #3aa8c7;
    }

    QFrame[frameShape="4"],
    QFrame[frameShape="5"] {
        color: #1a2d43;
        background-color: #1a2d43;
    }
    """
