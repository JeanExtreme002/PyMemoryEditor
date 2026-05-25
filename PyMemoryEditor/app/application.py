# -*- coding: utf-8 -*-
"""
Entry point for the PyMemoryEditor App.

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


class _PointerCursorFilter:
    """
    Application-wide event filter that gives every QPushButton a pointing-hand
    cursor on hover. Qt's QSS does not honor the CSS `cursor` property, so we
    set it imperatively when each button is polished by the style.
    """

    def __init__(self):
        from PySide6.QtCore import QObject

        # Build the filter as a real QObject subclass at construction time so
        # we don't pay the PySide6 import cost at module import.
        class _Impl(QObject):
            def eventFilter(self_inner, obj, event):  # noqa: N805
                from PySide6.QtCore import Qt, QEvent
                from PySide6.QtWidgets import QPushButton

                if event.type() == QEvent.Type.Polish and isinstance(obj, QPushButton):
                    obj.setCursor(Qt.CursorShape.PointingHandCursor)
                return False

        self._impl = _Impl()

    def install_on(self, app):
        app.installEventFilter(self._impl)


def apply_dark_theme(app) -> None:
    """
    Apply a Cheat-Engine-flavored dark theme. We base everything on Qt's
    Fusion style so the look is identical across Windows/Linux/macOS instead
    of inheriting each platform's native widgets.
    """
    from PySide6.QtGui import QColor, QPalette
    from PySide6.QtWidgets import QStyleFactory

    app.setStyle(QStyleFactory.create("Fusion"))

    # Stash the filter on the app so it lives as long as the QApplication and
    # isn't garbage-collected mid-run.
    if not hasattr(app, "_pointer_cursor_filter"):
        app._pointer_cursor_filter = _PointerCursorFilter()
        app._pointer_cursor_filter.install_on(app)

    palette = QPalette()
    # Kali-inspired terminal palette: near-black backgrounds with a subtle cool
    # tint, teal/dragon accent instead of the stock Qt blue.
    bg = QColor(0x0F, 0x14, 0x19)  # window background (deep graphite)
    bg_alt = QColor(0x0A, 0x0E, 0x12)  # text/list backgrounds (terminal black)
    bg_button = QColor(0x1A, 0x21, 0x29)  # button base
    text = QColor(0xC9, 0xD1, 0xD9)
    text_dim = QColor(0x6E, 0x76, 0x81)
    accent = QColor(0x2D, 0xD4, 0xBF)  # selection / highlight (Kali teal)
    accent_text = QColor(0x08, 0x11, 0x14)
    border = QColor(0x1F, 0x2A, 0x33)

    palette.setColor(QPalette.Window, bg)
    palette.setColor(QPalette.WindowText, text)
    palette.setColor(QPalette.Base, bg_alt)
    palette.setColor(QPalette.AlternateBase, QColor(0x11, 0x16, 0x1C))
    palette.setColor(QPalette.ToolTipBase, bg)
    palette.setColor(QPalette.ToolTipText, text)
    palette.setColor(QPalette.Text, text)
    palette.setColor(QPalette.Button, bg_button)
    palette.setColor(QPalette.ButtonText, text)
    palette.setColor(QPalette.BrightText, QColor(0xF8, 0x71, 0x71))
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
QPushButton#primary, QPushButton#secondary, QPushButton#danger {
    padding: 7px 14px;
    min-height: 20px;
    font-weight: 600;
}
QPushButton#primary {
    background: %(accent)s;
    color: #08111A;
    font-weight: 700;
    border-color: %(accent)s;
}
QPushButton#primary:hover {
    background: #5EEAD4;
    border-color: #5EEAD4;
}
QPushButton#primary:pressed {
    background: #14B8A6;
    border-color: #14B8A6;
}
QPushButton#primary:disabled {
    background: transparent;
    color: %(text_dim)s;
    border-color: %(border)s;
}
QPushButton#secondary {
    background: transparent;
    color: %(accent)s;
    border: 1px solid %(accent)s;
}
QPushButton#secondary:hover {
    background: %(accent)s;
    color: #08111A;
}
QPushButton#secondary:pressed {
    background: #14B8A6;
    color: #08111A;
    border-color: #14B8A6;
}
QPushButton#secondary:disabled {
    background: transparent;
    color: %(text_dim)s;
    border-color: %(border)s;
}
QPushButton#danger {
    background: transparent;
    color: #F87171;
    border: 1px solid #5C2424;
}
QPushButton#danger:hover {
    background: rgba(248, 113, 113, 0.08);
    border-color: #F87171;
}
QPushButton#danger:pressed {
    background: rgba(248, 113, 113, 0.18);
    border-color: #F87171;
}
QPushButton#danger:disabled {
    background: transparent;
    color: %(text_dim)s;
    border-color: %(border)s;
}
QLineEdit, QComboBox, QSpinBox, QDoubleSpinBox, QPlainTextEdit, QTextEdit {
    background: %(bg_alt)s;
    border: 1px solid %(border)s;
    border-radius: 4px;
    padding: 4px 6px;
    selection-background-color: %(accent)s;
    selection-color: #08111A;
}
QLineEdit:focus, QComboBox:focus, QSpinBox:focus, QDoubleSpinBox:focus {
    border-color: %(accent)s;
}
QComboBox QAbstractItemView {
    background: %(bg_alt)s;
    border: 1px solid %(border)s;
    selection-background-color: %(accent)s;
    selection-color: #08111A;
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
    alternate-background-color: #11161C;
    gridline-color: %(border)s;
    border: 1px solid %(border)s;
    border-radius: 4px;
    selection-background-color: %(accent)s;
    selection-color: #08111A;
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
QMenu::item:selected { background: %(accent)s; color: #08111A; }
QCheckBox::indicator, QRadioButton::indicator { width: 14px; height: 14px; }
QSplitter::handle { background: %(border)s; border-radius: 2px; margin: 2px; }
QSplitter::handle:horizontal { width: 4px; }
QSplitter::handle:vertical { height: 4px; }
QSplitter::handle:hover { background: #3A4954; }
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

    from ._icon import app_icon

    app = QApplication.instance() or QApplication(argv)
    app.setApplicationName("PyMemoryEditor")
    app.setApplicationDisplayName("PyMemoryEditor App")
    app.setWindowIcon(app_icon())
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
