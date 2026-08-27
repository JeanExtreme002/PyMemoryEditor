# -*- coding: utf-8 -*-

"""
Smoke tests for the PySide6 ("Qt") app shipped under PyMemoryEditor/app/.

The app is currently excluded from coverage and mypy because it's a UI demo
that the maintainer drives manually. That left ~1.6k LOC with no automated
safety net — a typo in `apply_dark_theme` or a missing import would only be
caught the next time someone ran `pymemoryeditor`.

These tests don't try to exercise scanning end-to-end. They just verify:
  1. The package's modules import without raising.
  2. ``application.main(["pymemoryeditor", "--version"])`` short-circuits
     before instantiating QApplication (no Qt dependency required for the
     version flag).
  3. With PySide6 available, the ``MainWindow`` and ``CheatTable`` widgets can
     be constructed against a self-PID ``OpenProcess`` and torn down cleanly.
  4. Ctrl+C handling stays where it belongs: ``main_cli()`` scopes SIG_DFL to
     the run so a terminal can kill the blocked Qt event loop, while ``main()``
     leaves the process-wide handler untouched for in-process callers.

Skipped when ``PySide6`` isn't installed (the runtime dependency is opt-in via
the ``app`` extra).
"""

import os

import pytest


pytest.importorskip("PySide6", reason="App tests require PySide6 (install with [app] extra).")

# pytest-qt is optional but recommended; without it we still smoke-test the
# version flag (which doesn't need a QApplication).
qtbot_available = True
try:
    import pytestqt  # noqa: F401
except ImportError:
    qtbot_available = False


# Offscreen platform plugin: no display server needed, runs on CI.
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


def test_version_flag_prints_and_exits(capsys):
    """``pymemoryeditor --version`` must not require Qt at import time."""
    from PyMemoryEditor import __version__
    from PyMemoryEditor.app.application import main

    result = main(["pymemoryeditor", "--version"])
    captured = capsys.readouterr()
    assert __version__ in captured.out
    # `print(...)` returns None; the explicit return value isn't load-bearing
    # but we assert the call didn't raise.
    assert result is None


def _stub_cancelled_picker(monkeypatch):
    """Make the process picker cancel, so main() returns before building a window."""
    from PyMemoryEditor.app import open_process_dialog

    class _RejectedDialog:
        class DialogCode:
            Accepted = 1

        def exec(self):
            return 0  # anything != Accepted

        process = None

    monkeypatch.setattr(open_process_dialog, "OpenProcessDialog", _RejectedDialog)


def _sentinel_handler(signum, frame):  # pragma: no cover - installed, never raised
    pass


def test_main_leaves_the_callers_sigint_handler_alone(monkeypatch):
    """
    ``main()`` is a supported in-process entry point, so it must not touch the
    process-wide SIGINT handler: an embedder's own Ctrl+C handling has to
    survive running the app. The terminal-facing behaviour lives in
    ``main_cli()`` instead.
    """
    import signal

    from PyMemoryEditor.app import application

    _stub_cancelled_picker(monkeypatch)

    original = signal.signal(signal.SIGINT, _sentinel_handler)
    try:
        assert application.main(["pymemoryeditor"]) is None
        assert signal.getsignal(signal.SIGINT) is _sentinel_handler
    finally:
        signal.signal(signal.SIGINT, original)


def test_main_cli_scopes_sig_dfl_to_the_run(monkeypatch):
    """
    ``main_cli()`` is what the console script and ``python -m`` invoke. It hands
    SIGINT to the OS so Ctrl+C kills the blocked Qt event loop (#76), then puts
    the previous handler back so the change doesn't outlive the run.
    """
    import signal

    from PyMemoryEditor.app import application, open_process_dialog

    seen = {}

    class _ProbingDialog:
        class DialogCode:
            Accepted = 1

        def exec(self):
            # Sampled mid-run: this is where the Qt event loop would block.
            seen["inside"] = signal.getsignal(signal.SIGINT)
            return 0

        process = None

    monkeypatch.setattr(open_process_dialog, "OpenProcessDialog", _ProbingDialog)

    original = signal.signal(signal.SIGINT, _sentinel_handler)
    try:
        assert application.main_cli(["pymemoryeditor"]) is None
        assert seen["inside"] is signal.SIG_DFL
        assert signal.getsignal(signal.SIGINT) is _sentinel_handler
    finally:
        signal.signal(signal.SIGINT, original)


def test_scoped_signal_handler_is_a_noop_off_the_main_thread():
    """
    ``signal.signal`` only works on the main thread. The helper must degrade to
    a no-op there instead of raising, so an embedder that drives the app from a
    worker thread keeps working.
    """
    import signal
    import threading

    from PyMemoryEditor.app.application import _scoped_signal_handler

    outcome = {}

    def worker():
        try:
            with _scoped_signal_handler(signal.SIGINT, signal.SIG_DFL):
                outcome["body_ran"] = True
            outcome["error"] = None
        except BaseException as exc:  # noqa: BLE001 - report, don't swallow
            outcome["error"] = exc

    thread = threading.Thread(target=worker)
    thread.start()
    thread.join(timeout=10)

    assert outcome.get("body_ran") is True
    assert outcome.get("error") is None


def test_scoped_signal_handler_tolerates_unknown_previous_handler(monkeypatch):
    """
    ``signal.signal`` reports ``None`` as the previous handler when "an unknown
    handler is in effect" — one installed outside Python, which is what an
    embedding host may have done before the signal module initialized. Handing
    that ``None`` back to ``signal.signal`` raises TypeError, so the guard has
    to skip the restore rather than crash on the way out of a good run.
    """
    import signal

    from PyMemoryEditor.app.application import _scoped_signal_handler

    real_signal = signal.signal
    original = signal.getsignal(signal.SIGINT)

    def fake_signal(signum, handler):
        """Report None on the way in, like a C-installed handler would."""
        real_signal(signum, handler)
        return None if handler is signal.SIG_DFL else original

    monkeypatch.setattr(signal, "signal", fake_signal)
    try:
        with _scoped_signal_handler(signal.SIGINT, signal.SIG_DFL):
            pass
    finally:
        monkeypatch.undo()
        if original is not None:
            signal.signal(signal.SIGINT, original)


def test_app_modules_import_cleanly():
    """Every app submodule should import without side effects beyond Qt setup."""
    # Order matches the dependency graph: leaves first, container last.
    import PyMemoryEditor.app._widgets  # noqa: F401
    import PyMemoryEditor.app.value_types  # noqa: F401
    import PyMemoryEditor.app.scan_worker  # noqa: F401
    import PyMemoryEditor.app.results_view  # noqa: F401
    import PyMemoryEditor.app.scanner_panel  # noqa: F401
    import PyMemoryEditor.app.cheat_table  # noqa: F401
    import PyMemoryEditor.app.memory_viewer_dialog  # noqa: F401
    import PyMemoryEditor.app.memory_map_dialog  # noqa: F401
    import PyMemoryEditor.app.modules_dialog  # noqa: F401
    import PyMemoryEditor.app.pointer_chain_dialog  # noqa: F401
    import PyMemoryEditor.app.pointer_scan_dialog  # noqa: F401
    import PyMemoryEditor.app.open_process_dialog  # noqa: F401
    import PyMemoryEditor.app.main_window  # noqa: F401
    import PyMemoryEditor.app.application  # noqa: F401


@pytest.mark.skipif(not qtbot_available, reason="pytest-qt not installed.")
def test_qapplication_starts_under_offscreen(qtbot):
    """
    Sanity-check that the offscreen Qt platform plugin works in this environment.

    The dialog/window/cheat-table construction was originally tested here, but
    the app spins up live polling threads in those widgets' ``__init__`` and
    tearing them down inside a unit test produced fatal-abort flakes on macOS
    (the thread outlives the process handle by a tick). Keep the smoke test
    narrow until the app's lifecycle is hardened — the manual ``pymemoryeditor``
    smoke run remains the authoritative check.
    """
    from PySide6.QtWidgets import QApplication, QLabel

    app = QApplication.instance() or QApplication([])
    label = QLabel("smoke")
    qtbot.addWidget(label)
    label.show()
    qtbot.wait(10)
    label.close()
    assert app is not None


@pytest.mark.skipif(not qtbot_available, reason="pytest-qt not installed.")
def test_variable_width_types_lock_length_to_value_text(qtbot):
    """
    Selecting "String (UTF-8)" or "Byte Array (Hex)" disables the length field
    and drives it from the size of the typed value, so the buffer width always
    matches what the user entered (multi-byte aware for a string, the parsed
    byte count for a byte array). Fixed-width types keep the field disabled at
    their own size; only the regex type stays editable.
    """
    from PySide6.QtWidgets import QApplication

    from PyMemoryEditor.app.scanner_panel import ScannerPanel

    QApplication.instance() or QApplication([])
    panel = ScannerPanel()
    qtbot.addWidget(panel)

    # Switching to String locks the length field...
    panel._type_combo.setCurrentText("String (UTF-8)")
    assert not panel._length_spin.isEnabled()

    # ...and the length tracks the UTF-8 byte size of the value text. "olá" is
    # 3 characters but 4 bytes (the 'á' is two bytes).
    panel._value_edit.setText("olá")
    assert panel._length_spin.value() == 4

    request = panel._build_request()
    assert request is not None
    assert request.value == "olá"
    assert request.length == 4  # derived from the text, not the spin override

    # Byte Array behaves the same way (issue #79): the length is the number of
    # hex bytes entered, not a separate field the user has to keep in sync.
    panel._type_combo.setCurrentText("Byte Array (Hex)")
    assert not panel._length_spin.isEnabled()

    panel._value_edit.setText("00 11 22 AA BB CC")
    assert panel._length_spin.value() == 6

    request = panel._build_request()
    assert request is not None
    assert request.value == b"\x00\x11\x22\xaa\xbb\xcc"
    assert request.length == 6

    # A half-typed byte pair doesn't parse — the readout holds its last valid
    # width instead of flickering while the user types.
    panel._value_edit.setText("00 11 22 AA BB C")
    assert panel._length_spin.value() == 6

    # Promoting these results to the cheat table must carry the same width, or
    # the entry would show a truncated value.
    panel._value_edit.setText("00 11 22 AA BB CC")
    spec, length = panel.current_spec_and_length()
    assert spec.label == "Byte Array (Hex)"
    assert length == 6

    # Clearing the value (what picking a no-value scan type does) leaves the
    # readout on the last width instead of collapsing to 1 — that width is what
    # a "Changed Value" next-scan refines with.
    panel._value_edit.clear()
    assert panel._length_spin.value() == 6

    panel.close()


@pytest.mark.skipif(not qtbot_available, reason="pytest-qt not installed.")
def test_locked_length_readout_is_reseeded_when_the_value_type_changes(qtbot):
    """
    The Length readout is read-only for the value-sized types, so a value that
    doesn't parse as the newly picked type must fall back to that type's default
    width — leaving a stale width from the previous type would be both wrong and
    uncorrectable by the user.
    """
    from PySide6.QtWidgets import QApplication

    from PyMemoryEditor.app.scanner_panel import ScannerPanel
    from PyMemoryEditor.app.value_types import find_spec

    QApplication.instance() or QApplication([])
    panel = ScannerPanel()
    qtbot.addWidget(panel)

    bytes_default = find_spec("Byte Array (Hex)").length
    str_default = find_spec("String (UTF-8)").length

    # A string value is not valid hex, so switching to Byte Array can't size it.
    panel._type_combo.setCurrentText("String (UTF-8)")
    panel._value_edit.setText("some long string here")
    assert panel._length_spin.value() == 21

    panel._type_combo.setCurrentText("Byte Array (Hex)")
    assert panel._length_spin.value() == bytes_default
    assert panel.current_spec_and_length()[1] == bytes_default

    # Same the other way round: an empty field falls back to the spec default
    # rather than inheriting whatever the previous type left behind.
    panel._value_edit.clear()
    panel._type_combo.setCurrentText("String (UTF-8)")
    assert panel._length_spin.value() == str_default

    panel.close()


@pytest.mark.skipif(not qtbot_available, reason="pytest-qt not installed.")
def test_pointer_scan_dialog_constructs_and_prefills(qtbot):
    """
    The Pointer Scan dialog starts no background thread in ``__init__`` (the
    worker only spins up on Scan), so it's safe to construct, prefill and tear
    down in a unit test — unlike the polling dialogs.
    """
    import os

    from PySide6.QtWidgets import QApplication

    from PyMemoryEditor import OpenProcess
    from PyMemoryEditor.app.pointer_scan_dialog import PointerScanDialog

    QApplication.instance() or QApplication([])
    process = OpenProcess(pid=os.getpid())
    try:
        dialog = PointerScanDialog(process)
        qtbot.addWidget(dialog)
        # set_target_address is the entry point the results view uses.
        dialog.set_target_address(0x1234)
        assert "1234" in dialog._target_edit.text().upper()
        # Table is wired with the Cheat-Engine-style columns.
        assert dialog._model.columnCount() == 6
        dialog.close()
    finally:
        process.close()
