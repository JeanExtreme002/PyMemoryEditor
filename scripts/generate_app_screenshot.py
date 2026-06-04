#!/usr/bin/env python3
"""
Regenerate the README screenshot of the PyMemoryEditor app.

This is a maintainer-only helper — it is intentionally kept out of the
published package (see the sdist/wheel excludes in ``pyproject.toml``).

It launches the Qt app attached to *this* Python process (so it works on
every platform without special entitlements), stages a believable scan +
cheat-table scenario, and grabs the window to
``assets/screenshots/app.png``.

Usage:
    pip install "PyMemoryEditor[app]"
    python scripts/generate_app_screenshot.py
"""
import os
import sys
from pathlib import Path

from PySide6.QtCore import QPointF, QRectF, Qt, QTimer
from PySide6.QtGui import (
    QColor,
    QFont,
    QLinearGradient,
    QPainter,
    QPainterPath,
    QPen,
    QPixmap,
)
from PySide6.QtWidgets import (
    QApplication,
    QGraphicsDropShadowEffect,
    QGraphicsPixmapItem,
    QGraphicsScene,
)

from PyMemoryEditor import OpenProcess
from PyMemoryEditor.app._icon import app_icon
from PyMemoryEditor.app.application import DEFAULT_THEME_ID, apply_theme
from PyMemoryEditor.app.cheat_entry import CheatEntry
from PyMemoryEditor.app.main_window import MainWindow
from PyMemoryEditor.app.value_types import find_spec


REPO_ROOT = Path(__file__).resolve().parent.parent
OUTPUT_PATH = str(REPO_ROOT / "assets" / "screenshots" / "app.png")

# macOS-style window chrome, tuned to match the app's dark "Kali Teal" theme.
# The margin is kept just large enough to hold the (soft) drop shadow.
TITLE_BAR_HEIGHT = 40
CORNER_RADIUS = 11
SHADOW_BLUR = 30
SHADOW_OFFSET_Y = 10
SHADOW_MARGIN = 26
TITLE_BAR_TOP = "#11161C"
TITLE_BAR_BOTTOM = "#0A0E12"
TITLE_BAR_BORDER = "#1F2A33"
TITLE_TEXT = "PyMemoryEditor"
TITLE_TEXT_COLOR = "#6E7681"
TRAFFIC_LIGHTS = ("#FF5F57", "#FEBC2E", "#28C840")


def wrap_in_macos_frame(content: QPixmap) -> QPixmap:
    """Composite *content* into a macOS-style window (traffic lights, title
    bar, rounded corners, drop shadow) on a transparent canvas, with the
    tightest margin that still fits the shadow."""
    dpr = content.devicePixelRatio() or 1.0
    content.setDevicePixelRatio(1.0)  # draw the grab 1:1 in physical pixels

    def s(value):  # scale chrome metrics to match a possibly-retina grab
        return int(round(value * dpr))

    title_h = s(TITLE_BAR_HEIGHT)
    radius = s(CORNER_RADIUS)
    margin = s(SHADOW_MARGIN)

    win_w = content.width()
    win_h = content.height() + title_h

    window_pix = QPixmap(win_w, win_h)
    window_pix.fill(Qt.transparent)

    p = QPainter(window_pix)
    p.setRenderHint(QPainter.Antialiasing)
    p.setRenderHint(QPainter.SmoothPixmapTransform)

    path = QPainterPath()
    path.addRoundedRect(QRectF(0, 0, win_w, win_h), radius, radius)
    p.setClipPath(path)

    # Title bar gradient + content below it.
    gradient = QLinearGradient(0, 0, 0, title_h)
    gradient.setColorAt(0.0, QColor(TITLE_BAR_TOP))
    gradient.setColorAt(1.0, QColor(TITLE_BAR_BOTTOM))
    p.fillRect(QRectF(0, 0, win_w, title_h), gradient)
    p.drawPixmap(0, title_h, content)

    # Separator under the title bar.
    p.setPen(QPen(QColor(TITLE_BAR_BORDER), s(1)))
    p.drawLine(0, title_h, win_w, title_h)

    # Traffic lights.
    p.setPen(Qt.NoPen)
    dot_r = s(6.5)
    spacing = s(20)
    cx = s(22)
    cy = title_h / 2
    for color in TRAFFIC_LIGHTS:
        p.setBrush(QColor(color))
        p.drawEllipse(QPointF(cx, cy), dot_r, dot_r)
        cx += spacing

    # Centered title text.
    font = QFont(p.font())
    font.setPixelSize(s(13))
    font.setBold(True)
    p.setFont(font)
    p.setPen(QColor(TITLE_TEXT_COLOR))
    p.drawText(QRectF(0, 0, win_w, title_h), Qt.AlignCenter, TITLE_TEXT)

    # Hairline border around the whole window.
    p.setClipping(False)
    p.setBrush(Qt.NoBrush)
    p.setPen(QPen(QColor(TITLE_BAR_BORDER), s(1)))
    inset = s(0.5)
    p.drawRoundedRect(
        QRectF(inset, inset, win_w - s(1), win_h - s(1)), radius, radius
    )
    p.end()

    # Drop shadow on a transparent canvas via a graphics scene.
    scene = QGraphicsScene()
    item = QGraphicsPixmapItem(window_pix)
    shadow = QGraphicsDropShadowEffect()
    shadow.setBlurRadius(s(SHADOW_BLUR))
    shadow.setColor(QColor(0, 0, 0, 130))
    shadow.setOffset(0, s(SHADOW_OFFSET_Y))
    item.setGraphicsEffect(shadow)
    scene.addItem(item)

    final = QPixmap(win_w + margin * 2, win_h + margin * 2)
    final.fill(Qt.transparent)
    fp = QPainter(final)
    fp.setRenderHint(QPainter.Antialiasing)
    scene.render(
        fp,
        QRectF(0, 0, final.width(), final.height()),
        QRectF(-margin, -margin, final.width(), final.height()),
    )
    fp.end()
    return final

rows = [
    (0x000055EF6A1C0008, 100, 87),
    (0x000055EF6A1C0014, 100, 102),
    (0x000055EF6A24007C, 100, 64),
    (0x000055EF6A2400A0, 100, 113),
    (0x000055EF6A300120, 100, 95),
    (0x000055EF6A300C44, 100, 158),
    (0x00007F8E1A4B8010, 100, 41),
    (0x00007F8E1A4B8024, 100, 76),
    (0x00007F8E1A500088, 100, 132),
    (0x00007F8E1A5000F0, 100, 88),
    (0x00007F8E1A5C0114, 100, 200),
    (0x00007F8E1A6A8200, 100, 17),
    (0x00007F8E1A6A82C0, 100, 99),
    (0x00007F8E1A7B40A0, 100, 124),
    (0x00007F8E1A7B41B4, 100, 53),
    (0x00007F8E1A8C8050, 100, 181),
    (0x00007F8E1A9D0140, 100, 72),
    (0x00007F8E1AAE0090, 100, 145),
    (0x00007F8E1ABF0030, 100, 28),
] * 19

def populate_results(window):
    """Fill the Found Addresses table with believable refine-scan rows.

    Every current value is the scan target (100); the previous column varies
    so the screenshot reads as "lots of candidates converged onto 100".
    """
    spec = find_spec("4 Bytes (Int32)")
    model = window._results_model
    model.set_value_spec(spec)

    model.append_chunk([(addr, cur) for addr, cur, _ in rows])
    for i, (_, cur, prev) in enumerate(rows):
        model._previous[i] = prev
        model._values[i] = cur
    model.layoutChanged.emit()

    window._results_label.setText(f"Found {len(rows)} addresses.")
    window._scanner.set_has_results(True)


def populate_cheat_table(window):
    """Add a few saved entries — one frozen — with believable last values."""
    cheat = window._cheat
    entries = [
        (
            CheatEntry(
                description="Player HP",
                address=0x000055EF6A1C0008,
                spec_label="4 Bytes (Int32)",
                length=4,
                frozen=True,
                frozen_value=999,
            ),
            999,
        ),
        (
            CheatEntry(
                description="Ammo",
                address=0x000055EF6A1C0014,
                spec_label="4 Bytes (Int32)",
                length=4,
            ),
            42,
        ),
        (
            CheatEntry(
                description="Coins",
                address=0x000055EF6A24007C,
                spec_label="4 Bytes (Int32)",
                length=4,
            ),
            1337,
        ),
        (
            CheatEntry(
                description="Player Name",
                address=0x00007F8E1A500088,
                spec_label="String (UTF-8)",
                length=16,
            ),
            "JeanExtreme002",
        ),
    ]
    for entry, _ in entries:
        cheat.add_entry(entry)
    # Stamp last_value and refresh the value cells directly. Suspend
    # cellChanged so setText() doesn't trigger a write into the fake addresses.
    cheat._suspend_signals = True
    try:
        for row, (entry, value) in enumerate(entries):
            entry.last_value = value
            cheat._update_value_cell(row, entry)
    finally:
        cheat._suspend_signals = False


def main():
    app = QApplication.instance() or QApplication(sys.argv)
    app.setApplicationName("PyMemoryEditor")
    app.setApplicationDisplayName("PyMemoryEditor App")
    app.setOrganizationName("PyMemoryEditor")
    app.setWindowIcon(app_icon())
    apply_theme(app, DEFAULT_THEME_ID)

    process = OpenProcess(pid=os.getpid())
    window = MainWindow(process)
    window.resize(1280, 780)
    window.show()

    def shoot():
        app.processEvents()
        window._scanner._value_edit.setText("100")
        populate_results(window)
        populate_cheat_table(window)

        # Show a completed scan in the progress bar and status bar.
        window._progress.setValue(100)
        window._status.showMessage(f"Checked 81,750/82,350, kept {len(rows)}")

        # Stop background timers so they don't overwrite the staged values
        # between processEvents() and grab().
        try:
            window._heartbeat.stop()
        except Exception:
            pass
        try:
            window._cheat._publish_timer.stop()
            window._cheat._poller.stop()
        except Exception:
            pass

        app.processEvents()
        pixmap = wrap_in_macos_frame(window.grab())
        ok = pixmap.save(OUTPUT_PATH, "PNG")
        print(f"saved={ok} path={OUTPUT_PATH} size={pixmap.width()}x{pixmap.height()}")
        QTimer.singleShot(50, app.quit)

    # Let the event loop tick once so the window paints before we grab it.
    QTimer.singleShot(400, shoot)
    app.exec()


if __name__ == "__main__":
    main()
