# -*- coding: utf-8 -*-
"""
Entry point for the PyMemoryEditor Qt app.

A Cheat-Engine-inspired memory scanner built on PySide6 (Qt for Python),
working on Windows, Linux and macOS.
"""
import sys

from PyMemoryEditor import __version__


_QT_MISSING_HINT = (
    "PyMemoryEditor's Qt app requires PySide6 (Qt for Python).\n"
    "Install it with:\n"
    "    pip install PySide6\n"
    "or install PyMemoryEditor with the Qt extra:\n"
    '    pip install "PyMemoryEditor[app]"\n'
)


def _abort_if_qt_unavailable():
    """Import PySide6 with a friendly error if it isn't installed."""
    try:
        import PySide6  # noqa: F401
    except ImportError:
        sys.stderr.write(_QT_MISSING_HINT)
        sys.exit(2)


def apply_dark_theme(app) -> None:
    """
    Apply a Cheat-Engine-flavored dark theme. We base everything on Qt's
    Fusion style so the look is identical across Windows/Linux/macOS instead
    of inheriting each platform's native widgets.
    """
    from PySide6.QtGui import QColor, QPalette
    from PySide6.QtWidgets import QStyleFactory

    app.setStyle(QStyleFactory.create("Fusion"))

    palette = QPalette()
    bg = QColor(0x1E, 0x1F, 0x29)  # window background
    bg_alt = QColor(0x16, 0x17, 0x1F)  # text/list backgrounds
    bg_button = QColor(0x2B, 0x2D, 0x3E)  # button base
    text = QColor(0xE6, 0xE6, 0xEC)
    text_dim = QColor(0x9A, 0x9D, 0xB4)
    accent = QColor(0x6A, 0xA9, 0xFF)  # selection / highlight
    accent_text = QColor(0x0E, 0x0F, 0x17)
    border = QColor(0x33, 0x36, 0x4A)

    palette.setColor(QPalette.Window, bg)
    palette.setColor(QPalette.WindowText, text)
    palette.setColor(QPalette.Base, bg_alt)
    palette.setColor(QPalette.AlternateBase, QColor(0x1B, 0x1D, 0x29))
    palette.setColor(QPalette.ToolTipBase, bg)
    palette.setColor(QPalette.ToolTipText, text)
    palette.setColor(QPalette.Text, text)
    palette.setColor(QPalette.Button, bg_button)
    palette.setColor(QPalette.ButtonText, text)
    palette.setColor(QPalette.BrightText, QColor(0xFF, 0x4F, 0x4F))
    palette.setColor(QPalette.Link, accent)
    palette.setColor(QPalette.Highlight, accent)
    palette.setColor(QPalette.HighlightedText, accent_text)
    palette.setColor(QPalette.PlaceholderText, text_dim)
    palette.setColor(QPalette.Disabled, QPalette.Text, text_dim)
    palette.setColor(QPalette.Disabled, QPalette.ButtonText, text_dim)
    palette.setColor(QPalette.Disabled, QPalette.WindowText, text_dim)
    app.setPalette(palette)

    app.setStyleSheet(
        STYLE_SHEET
        % {
            "bg": bg.name(),
            "bg_alt": bg_alt.name(),
            "bg_button": bg_button.name(),
            "text": text.name(),
            "text_dim": text_dim.name(),
            "accent": accent.name(),
            "border": border.name(),
        }
    )


STYLE_SHEET = """
QToolTip {
    color: %(text)s;
    background-color: %(bg)s;
    border: 1px solid %(border)s;
    padding: 4px;
}
QGroupBox {
    border: 1px solid %(border)s;
    border-radius: 6px;
    margin-top: 14px;
    padding-top: 8px;
    font-weight: 600;
}
QGroupBox::title {
    subcontrol-origin: margin;
    subcontrol-position: top left;
    padding: 0 6px;
    color: %(accent)s;
}
QPushButton {
    background: %(bg_button)s;
    color: %(text)s;
    border: 1px solid %(border)s;
    border-radius: 4px;
    padding: 5px 12px;
}
QPushButton:hover { border-color: %(accent)s; }
QPushButton:pressed { background: %(bg)s; }
QPushButton:disabled { color: %(text_dim)s; border-color: %(border)s; }
QPushButton#primary {
    background: %(accent)s;
    color: #0E0F17;
    font-weight: 700;
    border-color: %(accent)s;
}
QPushButton#primary:hover { background: #82B6FF; }
QPushButton#danger { color: #FF8585; }
QLineEdit, QComboBox, QSpinBox, QDoubleSpinBox, QPlainTextEdit, QTextEdit {
    background: %(bg_alt)s;
    border: 1px solid %(border)s;
    border-radius: 4px;
    padding: 4px 6px;
    selection-background-color: %(accent)s;
    selection-color: #0E0F17;
}
QLineEdit:focus, QComboBox:focus, QSpinBox:focus, QDoubleSpinBox:focus {
    border-color: %(accent)s;
}
QComboBox QAbstractItemView {
    background: %(bg_alt)s;
    border: 1px solid %(border)s;
    selection-background-color: %(accent)s;
    selection-color: #0E0F17;
}
QHeaderView::section {
    background: %(bg)s;
    color: %(text_dim)s;
    border: none;
    border-right: 1px solid %(border)s;
    border-bottom: 1px solid %(border)s;
    padding: 4px 8px;
    font-weight: 600;
}
QTableView, QTreeView, QListView {
    background: %(bg_alt)s;
    alternate-background-color: #1B1D29;
    gridline-color: %(border)s;
    border: 1px solid %(border)s;
    border-radius: 4px;
    selection-background-color: %(accent)s;
    selection-color: #0E0F17;
}
QTabWidget::pane {
    border: 1px solid %(border)s;
    border-radius: 4px;
    top: -1px;
}
QTabBar::tab {
    background: %(bg)s;
    color: %(text_dim)s;
    border: 1px solid %(border)s;
    border-bottom: none;
    padding: 6px 14px;
    border-top-left-radius: 4px;
    border-top-right-radius: 4px;
}
QTabBar::tab:selected {
    background: %(bg_alt)s;
    color: %(accent)s;
}
QProgressBar {
    background: %(bg_alt)s;
    border: 1px solid %(border)s;
    border-radius: 4px;
    text-align: center;
    color: %(text)s;
    height: 16px;
}
QProgressBar::chunk {
    background-color: %(accent)s;
    border-radius: 3px;
}
QStatusBar {
    background: %(bg)s;
    color: %(text_dim)s;
    border-top: 1px solid %(border)s;
}
QMenuBar { background: %(bg)s; }
QMenuBar::item:selected { background: %(bg_button)s; }
QMenu { background: %(bg)s; border: 1px solid %(border)s; }
QMenu::item:selected { background: %(accent)s; color: #0E0F17; }
QCheckBox::indicator, QRadioButton::indicator { width: 14px; height: 14px; }
QSplitter::handle { background: %(border)s; }
QSplitter::handle:horizontal { width: 2px; }
QSplitter::handle:vertical { height: 2px; }
QLabel#hint { color: %(text_dim)s; }
QLabel#processBadge {
    background: %(bg_alt)s;
    border: 1px solid %(accent)s;
    border-radius: 4px;
    padding: 4px 8px;
    color: %(accent)s;
    font-weight: 700;
}
"""


def main(argv=None):
    """
    Entry point for the ``pymemoryeditor`` console script.

    ``argv`` defaults to ``sys.argv`` so packaging tools (which call
    ``main()`` with no arguments) keep working. Tests and embedders can pass
    an explicit list — previously a positional ``*args`` was accepted but
    ignored, which made the parameter meaningless.
    """
    if argv is None:
        argv = sys.argv

    if len(argv) > 1 and argv[1].strip() in ["--version", "-v"]:
        return print(__version__)

    _abort_if_qt_unavailable()

    from PySide6.QtWidgets import QApplication

    from .main_window import MainWindow
    from .open_process_dialog import OpenProcessDialog

    app = QApplication.instance() or QApplication(argv)
    app.setApplicationName("PyMemoryEditor")
    app.setApplicationDisplayName("PyMemoryEditor — Qt App")
    apply_dark_theme(app)

    picker = OpenProcessDialog()
    if picker.exec() != picker.DialogCode.Accepted:
        return

    process = picker.process
    if process is None:
        return

    window = MainWindow(process)
    window.show()
    try:
        app.exec()
    finally:
        try:
            process.close()
        except Exception:
            pass


if __name__ == "__main__":
    main()
