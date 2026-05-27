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

from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QApplication

from PyMemoryEditor import OpenProcess
from PyMemoryEditor.app._icon import app_icon
from PyMemoryEditor.app.application import DEFAULT_THEME_ID, apply_theme
from PyMemoryEditor.app.cheat_entry import CheatEntry
from PyMemoryEditor.app.main_window import MainWindow
from PyMemoryEditor.app.value_types import find_spec


REPO_ROOT = Path(__file__).resolve().parent.parent
OUTPUT_PATH = str(REPO_ROOT / "assets" / "screenshots" / "app.png")

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
        pixmap = window.grab()
        ok = pixmap.save(OUTPUT_PATH, "PNG")
        print(f"saved={ok} path={OUTPUT_PATH} size={pixmap.width()}x{pixmap.height()}")
        QTimer.singleShot(50, app.quit)

    # Let the event loop tick once so the window paints before we grab it.
    QTimer.singleShot(400, shoot)
    app.exec()


if __name__ == "__main__":
    main()
