# -*- coding: utf-8 -*-
"""
Entry point for the PyMemoryEditor App.

A Cheat-Engine-inspired memory scanner built on PySide6 (Qt for Python),
working on Windows, Linux and macOS.
"""
import sys
from dataclasses import dataclass

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


@dataclass(frozen=True)
class Theme:
    """A flat palette describing every color the app's QSS and QPalette need.

    Hex strings are stored verbatim so they can be substituted into the QSS
    template without re-formatting; QColor accepts the same form when we feed
    them into QPalette.
    """

    id: str
    name: str
    bg: str
    bg_alt: str
    bg_button: str
    alt_base: str
    text: str
    text_dim: str
    bright_text: str
    accent: str
    accent_text: str
    accent_hover: str
    accent_pressed: str
    border: str
    splitter_hover: str
    danger: str
    danger_border: str


_KALI_TEAL = Theme(
    id="kali_teal",
    name="Kali Teal",
    bg="#0F1419",
    bg_alt="#0A0E12",
    bg_button="#1A2129",
    alt_base="#11161C",
    text="#C9D1D9",
    text_dim="#6E7681",
    bright_text="#F87171",
    accent="#2DD4BF",
    accent_text="#08111A",
    accent_hover="#5EEAD4",
    accent_pressed="#14B8A6",
    border="#1F2A33",
    splitter_hover="#3A4954",
    danger="#F87171",
    danger_border="#5C2424",
)

_DRACULA = Theme(
    id="dracula",
    name="Dracula",
    bg="#282A36",
    bg_alt="#1E1F29",
    bg_button="#383A4D",
    alt_base="#2D2F40",
    text="#F8F8F2",
    text_dim="#6272A4",
    bright_text="#FF5555",
    accent="#BD93F9",
    accent_text="#282A36",
    accent_hover="#D7BAFF",
    accent_pressed="#9D7BD6",
    border="#44475A",
    splitter_hover="#6272A4",
    danger="#FF5555",
    danger_border="#5C2424",
)

_TOKYO_NIGHT = Theme(
    id="tokyo_night",
    name="Tokyo Night",
    bg="#1A1B26",
    bg_alt="#16161E",
    bg_button="#24283B",
    alt_base="#1F2335",
    text="#C0CAF5",
    text_dim="#565F89",
    bright_text="#F7768E",
    accent="#7DCFFF",
    accent_text="#16161E",
    accent_hover="#A8E0FF",
    accent_pressed="#5DAFE0",
    border="#2A2E45",
    splitter_hover="#414868",
    danger="#F7768E",
    danger_border="#5C2434",
)

_MATRIX_GREEN = Theme(
    id="matrix_green",
    name="Matrix Green",
    bg="#0A0E0A",
    bg_alt="#050805",
    bg_button="#141A14",
    alt_base="#0B100B",
    text="#C8E6C9",
    text_dim="#5A7060",
    bright_text="#FF5555",
    accent="#00FF41",
    accent_text="#050805",
    accent_hover="#5EFF7E",
    accent_pressed="#00CC33",
    border="#1B2A1B",
    splitter_hover="#2B3F2B",
    danger="#FF5555",
    danger_border="#5C2424",
)

_CYBERPUNK = Theme(
    id="cyberpunk",
    name="Cyberpunk",
    bg="#0E0E14",
    bg_alt="#08080D",
    bg_button="#1A1A24",
    alt_base="#15151F",
    text="#E8E8F0",
    text_dim="#6E6E80",
    bright_text="#FF5C5C",
    accent="#FF2A6D",
    accent_text="#0E0E14",
    accent_hover="#FF5C8E",
    accent_pressed="#D11857",
    border="#2A2A38",
    splitter_hover="#3A3A4A",
    danger="#FF5C5C",
    danger_border="#5C2424",
)


THEMES = {
    t.id: t
    for t in (_KALI_TEAL, _DRACULA, _TOKYO_NIGHT, _MATRIX_GREEN, _CYBERPUNK)
}
DEFAULT_THEME_ID = _KALI_TEAL.id


def _hex_to_rgba(hex_str: str, alpha: float) -> str:
    """Format `#RRGGBB` as `rgba(R, G, B, alpha)` for Qt QSS."""
    r = int(hex_str[1:3], 16)
    g = int(hex_str[3:5], 16)
    b = int(hex_str[5:7], 16)
    return f"rgba({r}, {g}, {b}, {alpha})"


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


def apply_theme(app, theme_id: str = DEFAULT_THEME_ID) -> None:
    """
    Apply a named dark theme to ``app``. Falls back to the default theme if
    ``theme_id`` is unknown. We base everything on Qt's Fusion style so the
    look is identical across Windows/Linux/macOS instead of inheriting each
    platform's native widgets.
    """
    from PySide6.QtGui import QColor, QPalette
    from PySide6.QtWidgets import QStyleFactory

    theme = THEMES.get(theme_id, THEMES[DEFAULT_THEME_ID])

    app.setStyle(QStyleFactory.create("Fusion"))

    # Stash the cursor filter on the app so it lives as long as the
    # QApplication and isn't garbage-collected mid-run. Idempotent across
    # theme switches.
    if not hasattr(app, "_pointer_cursor_filter"):
        app._pointer_cursor_filter = _PointerCursorFilter()
        app._pointer_cursor_filter.install_on(app)

    palette = QPalette()
    palette.setColor(QPalette.Window, QColor(theme.bg))
    palette.setColor(QPalette.WindowText, QColor(theme.text))
    palette.setColor(QPalette.Base, QColor(theme.bg_alt))
    palette.setColor(QPalette.AlternateBase, QColor(theme.alt_base))
    palette.setColor(QPalette.ToolTipBase, QColor(theme.bg))
    palette.setColor(QPalette.ToolTipText, QColor(theme.text))
    palette.setColor(QPalette.Text, QColor(theme.text))
    palette.setColor(QPalette.Button, QColor(theme.bg_button))
    palette.setColor(QPalette.ButtonText, QColor(theme.text))
    palette.setColor(QPalette.BrightText, QColor(theme.bright_text))
    palette.setColor(QPalette.Link, QColor(theme.accent))
    palette.setColor(QPalette.Highlight, QColor(theme.accent))
    palette.setColor(QPalette.HighlightedText, QColor(theme.accent_text))
    palette.setColor(QPalette.PlaceholderText, QColor(theme.text_dim))
    palette.setColor(QPalette.Disabled, QPalette.Text, QColor(theme.text_dim))
    palette.setColor(QPalette.Disabled, QPalette.ButtonText, QColor(theme.text_dim))
    palette.setColor(QPalette.Disabled, QPalette.WindowText, QColor(theme.text_dim))
    app.setPalette(palette)

    app.setStyleSheet(
        STYLE_SHEET
        % {
            "bg": theme.bg,
            "bg_alt": theme.bg_alt,
            "bg_button": theme.bg_button,
            "alt_base": theme.alt_base,
            "text": theme.text,
            "text_dim": theme.text_dim,
            "accent": theme.accent,
            "accent_text": theme.accent_text,
            "accent_hover": theme.accent_hover,
            "accent_pressed": theme.accent_pressed,
            "border": theme.border,
            "splitter_hover": theme.splitter_hover,
            "danger": theme.danger,
            "danger_border": theme.danger_border,
            "danger_hover_bg": _hex_to_rgba(theme.danger, 0.08),
            "danger_pressed_bg": _hex_to_rgba(theme.danger, 0.18),
        }
    )


def apply_dark_theme(app) -> None:
    """Backward-compatible shim that applies the default dark theme."""
    apply_theme(app, DEFAULT_THEME_ID)


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
    color: %(accent_text)s;
    font-weight: 700;
    border-color: %(accent)s;
}
QPushButton#primary:hover {
    background: %(accent_hover)s;
    border-color: %(accent_hover)s;
}
QPushButton#primary:pressed {
    background: %(accent_pressed)s;
    border-color: %(accent_pressed)s;
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
    color: %(accent_text)s;
}
QPushButton#secondary:pressed {
    background: %(accent_pressed)s;
    color: %(accent_text)s;
    border-color: %(accent_pressed)s;
}
QPushButton#secondary:disabled {
    background: transparent;
    color: %(text_dim)s;
    border-color: %(border)s;
}
QPushButton#danger {
    background: transparent;
    color: %(danger)s;
    border: 1px solid %(danger_border)s;
}
QPushButton#danger:hover {
    background: %(danger_hover_bg)s;
    border-color: %(danger)s;
}
QPushButton#danger:pressed {
    background: %(danger_pressed_bg)s;
    border-color: %(danger)s;
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
    selection-color: %(accent_text)s;
}
QLineEdit:focus, QComboBox:focus, QSpinBox:focus, QDoubleSpinBox:focus {
    border-color: %(accent)s;
}
QComboBox QAbstractItemView {
    background: %(bg_alt)s;
    border: 1px solid %(border)s;
    selection-background-color: %(accent)s;
    selection-color: %(accent_text)s;
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
    alternate-background-color: %(alt_base)s;
    gridline-color: %(border)s;
    border: 1px solid %(border)s;
    border-radius: 4px;
    selection-background-color: %(accent)s;
    selection-color: %(accent_text)s;
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
QMenu::item:selected { background: %(accent)s; color: %(accent_text)s; }
QCheckBox::indicator, QRadioButton::indicator { width: 14px; height: 14px; }
QSplitter::handle { background: %(border)s; border-radius: 2px; margin: 2px; }
QSplitter::handle:horizontal { width: 4px; }
QSplitter::handle:vertical { height: 4px; }
QSplitter::handle:hover { background: %(splitter_hover)s; }
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

    from PySide6.QtCore import QSettings
    from PySide6.QtWidgets import QApplication

    from .main_window import MainWindow
    from .open_process_dialog import OpenProcessDialog

    from ._icon import app_icon

    app = QApplication.instance() or QApplication(argv)
    app.setApplicationName("PyMemoryEditor")
    app.setApplicationDisplayName("PyMemoryEditor App")
    # OrganizationName is required for QSettings() to resolve a stable path
    # on every platform.
    app.setOrganizationName("PyMemoryEditor")
    app.setWindowIcon(app_icon())

    saved_theme = str(QSettings().value("theme", DEFAULT_THEME_ID))
    apply_theme(app, saved_theme)

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
