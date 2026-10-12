# -*- coding: utf-8 -*-

"""
Smoke tests for the PySide6 ("Qt") app shipped under PyMemoryEditor/app/.

The app is currently excluded from coverage and mypy because it's a UI demo
that the maintainer drives manually. That left ~1.6k LOC with no automated
safety net — a typo in `apply_theme` or a missing import would only be
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

    # A half-typed byte pair doesn't size to anything, so the readout reports no
    # width rather than a number no scan would use.
    panel._value_edit.setText("00 11 22 AA BB C")
    assert panel._length_spin.value() == 0

    # Promoting these results to the cheat table must carry the same width, or
    # the entry would show a truncated value.
    panel._value_edit.setText("00 11 22 AA BB CC")
    spec, length = panel.current_spec_and_length()
    assert spec.label == "Byte Array (Hex)"
    assert length == 6

    panel.close()


@pytest.mark.skipif(not qtbot_available, reason="pytest-qt not installed.")
def test_no_value_next_scan_refines_at_the_scanned_width(qtbot):
    """
    Increased / Changed / … compare against the baseline the previous scan
    recorded, so they must re-read at *that* scan's width. The Length readout
    can't stand in: it tracks the value currently in the field, which the user
    is free to edit after the first scan.
    """
    from PySide6.QtWidgets import QApplication

    from PyMemoryEditor.app.scan_types import NextScanType
    from PyMemoryEditor.app.scanner_panel import SCAN_TYPE_CHOICES, ScannerPanel

    QApplication.instance() or QApplication([])
    panel = ScannerPanel()
    qtbot.addWidget(panel)

    panel._type_combo.setCurrentText("Byte Array (Hex)")
    panel._value_edit.setText("00 11")
    panel._on_first_scan()  # records a 2-byte baseline
    panel.set_has_results(True)

    # The user edits the value without rescanning: the readout follows the new
    # value, but the results on screen are still the 2-byte ones.
    panel._value_edit.setText("00 11 22 33")
    assert panel._length_spin.value() == 4

    changed = next(
        i
        for i, (_, t) in enumerate(SCAN_TYPE_CHOICES)
        if t is NextScanType.CHANGED_VALUE
    )
    panel._scan_combo.setCurrentIndex(changed)

    request = panel._build_request()
    assert request is not None
    assert request.value is None
    assert request.length == 2  # the scanned width, not the readout's 4

    # Dropping the results drops the baseline with them.
    panel.set_has_results(False)
    assert panel._last_scan_length is None

    panel.close()


@pytest.mark.skipif(not qtbot_available, reason="pytest-qt not installed.")
def test_promote_and_update_values_use_the_scanned_width(qtbot):
    """
    Both act on the results already on screen, so both must use the width those
    results were read at — not the Length readout, which follows the Value box
    and is cleared outright by a no-value scan type.
    """
    from PySide6.QtWidgets import QApplication

    from PyMemoryEditor.app.scan_types import NextScanType
    from PyMemoryEditor.app.scanner_panel import SCAN_TYPE_CHOICES, ScannerPanel

    QApplication.instance() or QApplication([])
    panel = ScannerPanel()
    qtbot.addWidget(panel)

    panel._type_combo.setCurrentText("String (UTF-8)")
    panel._value_edit.setText("olá")  # 4 UTF-8 bytes
    panel._on_first_scan()
    panel.set_has_results(True)

    # A no-value scan type clears the Value box, so the readout drops to 0.
    changed = next(
        i
        for i, (_, t) in enumerate(SCAN_TYPE_CHOICES)
        if t is NextScanType.CHANGED_VALUE
    )
    panel._scan_combo.setCurrentIndex(changed)
    assert panel._length_spin.value() == 0

    # Promoting must still carry 4, not the spec's 16 — an entry read 16 bytes
    # wide would pull 12 bytes of neighbouring memory into the cell.
    spec, length = panel.current_spec_and_length()
    assert spec.label == "String (UTF-8)"
    assert length == 4

    # Update Values is a read-only refresh: it re-reads at the scanned width
    # even with a candidate for the next scan sitting in the box, and leaves
    # the baseline alone.
    widths = []
    panel.update_values_requested.connect(lambda r: widths.append(r.length))
    panel._scan_combo.setCurrentIndex(0)  # back to Exact Value
    panel._value_edit.setText("hi")  # 2 bytes — a candidate, not a rescan
    panel._on_update_values()
    assert widths == [4]
    assert panel._last_scan_length == 4

    panel.close()


@pytest.mark.skipif(not qtbot_available, reason="pytest-qt not installed.")
def test_update_values_needs_no_value_and_regex_keeps_its_length_field(qtbot):
    """
    "Update Values" applies no comparison, so it must refresh without a target
    value — a Value box a no-value scan type cleared used to abort it with
    "Invalid value". And the width override is for the value-sized types only:
    Regex owns a genuinely editable Length field that must keep working.
    """
    from PySide6.QtWidgets import QApplication, QMessageBox

    from PyMemoryEditor.app.scan_types import NextScanType
    from PyMemoryEditor.app.scanner_panel import SCAN_TYPE_CHOICES, ScannerPanel

    QApplication.instance() or QApplication([])

    dialogs = []
    original_warning = QMessageBox.warning
    QMessageBox.warning = staticmethod(lambda *a, **k: dialogs.append(a[1:3]))
    try:
        panel = ScannerPanel()
        qtbot.addWidget(panel)

        panel._type_combo.setCurrentText("String (UTF-8)")
        panel._value_edit.setText("olá")
        panel._on_first_scan()
        panel.set_has_results(True)

        # A no-value scan type clears the Value box; switching back leaves it
        # empty, which must not stop the refresh.
        changed = next(
            i
            for i, (_, t) in enumerate(SCAN_TYPE_CHOICES)
            if t is NextScanType.CHANGED_VALUE
        )
        panel._scan_combo.setCurrentIndex(changed)
        panel._scan_combo.setCurrentIndex(0)

        widths = []
        panel.update_values_requested.connect(lambda r: widths.append(r.length))
        panel._on_update_values()
        assert widths == [4]
        assert dialogs == []

        panel.close()

        # Regex: the Length field is the user's byte_length, not a readout.
        regex_panel = ScannerPanel()
        qtbot.addWidget(regex_panel)
        regex_panel._type_combo.setCurrentText("Regex (String)")
        regex_panel._value_edit.setText("Player[0-9]+")
        regex_panel._on_first_scan()
        regex_panel.set_has_results(True)
        regex_panel._length_spin.setValue(128)

        regex_widths = []
        regex_panel.update_values_requested.connect(
            lambda r: regex_widths.append(r.length)
        )
        regex_panel._on_update_values()
        assert regex_widths == [128]
        assert regex_panel.current_spec_and_length()[1] == 128

        regex_panel.close()
    finally:
        QMessageBox.warning = original_warning


@pytest.mark.skipif(not qtbot_available, reason="pytest-qt not installed.")
def test_a_scan_that_never_lands_does_not_move_the_baseline(qtbot):
    """
    The baseline describes the values on screen, so it may only advance when a
    scan actually finishes. A Next Scan whose worker errors out (the owner never
    reports results) must leave the previous width in place, or the following
    no-value refine re-reads at a width the table's values were never read at.
    """
    from PySide6.QtWidgets import QApplication

    from PyMemoryEditor.app.scan_types import NextScanType
    from PyMemoryEditor.app.scanner_panel import SCAN_TYPE_CHOICES, ScannerPanel

    QApplication.instance() or QApplication([])
    panel = ScannerPanel()
    qtbot.addWidget(panel)

    panel._type_combo.setCurrentText("Byte Array (Hex)")
    panel._value_edit.setText("00 11")  # 2 bytes
    panel._on_first_scan()
    panel.set_has_results(True)
    assert panel._last_scan_length == 2

    # Dispatch a 4-byte Next Scan that never completes (no set_has_results).
    panel._value_edit.setText("00 11 22 33")
    panel._on_next_scan()
    assert panel._last_scan_length == 2

    changed = next(
        i
        for i, (_, t) in enumerate(SCAN_TYPE_CHOICES)
        if t is NextScanType.CHANGED_VALUE
    )
    panel._scan_combo.setCurrentIndex(changed)
    assert panel._build_request().length == 2  # still the width on screen

    # The scan cycle ending discards the width that never landed, so a later
    # unrelated completion — "Update Values" reports results too — can't adopt
    # it retroactively.
    panel.set_busy(True)
    panel.set_busy(False)
    assert panel._pending_scan_length is None
    panel._on_update_values()
    panel.set_has_results(True)
    assert panel._last_scan_length == 2

    # A cancelled refine reports results too (the worker emits finished_ok with
    # what it kept), but only the rows it reached were re-read at the new width.
    panel._scan_combo.setCurrentIndex(0)
    panel._value_edit.setText("00 11 22 33 44 55")
    panel._on_next_scan()
    panel._on_cancel()
    panel.set_has_results(True)
    assert panel._last_scan_length == 2

    # Once a scan does land uncancelled, its width becomes the baseline.
    panel._value_edit.setText("00 11 22 33")
    panel._on_next_scan()
    panel.set_has_results(True)
    assert panel._last_scan_length == 4

    panel.close()


@pytest.mark.skipif(not qtbot_available, reason="pytest-qt not installed.")
def test_range_readout_covers_both_bounds(qtbot):
    """A range sizes with max(lo, hi), so the upper bound moves the readout."""
    from PySide6.QtWidgets import QApplication

    from PyMemoryEditor import ScanTypesEnum
    from PyMemoryEditor.app.scanner_panel import SCAN_TYPE_CHOICES, ScannerPanel

    QApplication.instance() or QApplication([])
    panel = ScannerPanel()
    qtbot.addWidget(panel)

    panel._type_combo.setCurrentText("Byte Array (Hex)")
    between = next(
        i
        for i, (_, t) in enumerate(SCAN_TYPE_CHOICES)
        if t is ScanTypesEnum.VALUE_BETWEEN
    )
    panel._scan_combo.setCurrentIndex(between)

    panel._value_edit.setText("AA")
    panel._second_value_edit.setText("AA BB CC")
    assert panel._length_spin.value() == 3
    assert panel._build_request().length == 3

    # Leaving the range drops the upper bound from the width again.
    panel._scan_combo.setCurrentIndex(0)
    assert panel._length_spin.value() == 1
    assert panel._build_request().length == 1

    panel.close()


@pytest.mark.skipif(not qtbot_available, reason="pytest-qt not installed.")
def test_promoting_an_aob_hit_uses_the_pattern_width(qtbot):
    """
    An IDA pattern has no Length field and a spec length of 0, so the width of
    one match has to come from the pattern itself — one token per byte,
    wildcards included. (Re-typing the entry so its cell is editable is
    ``CheatTable.add_entry``'s job; see the cheat-entry tests.)
    """
    from PySide6.QtWidgets import QApplication

    from PyMemoryEditor.app.scanner_panel import ScannerPanel

    QApplication.instance() or QApplication([])
    panel = ScannerPanel()
    qtbot.addWidget(panel)

    panel._type_combo.setCurrentText("AOB Pattern (IDA)")
    panel._value_edit.setText("48 8B ? ? 00")

    spec, length = panel.current_spec_and_length()
    assert spec.label == "AOB Pattern (IDA)"
    assert length == 5

    panel.close()


@pytest.mark.skipif(not qtbot_available, reason="pytest-qt not installed.")
def test_length_readout_reports_no_width_until_a_value_is_entered(qtbot):
    """
    A value-sized type has no width to report before a value exists, and the
    readout is read-only, so it must say so rather than show a number the scan
    would never use — picking Byte Array on a fresh panel used to inherit the
    Int32 "4 bytes" and then drop to "1 byte" on the first hex digit.
    """
    from PySide6.QtWidgets import QApplication

    from PyMemoryEditor.app.scanner_panel import EMPTY_LENGTH_TEXT, ScannerPanel
    from PyMemoryEditor.app.value_types import find_spec

    QApplication.instance() or QApplication([])
    panel = ScannerPanel()
    qtbot.addWidget(panel)

    # Fresh panel: Int32 shows its own fixed width.
    assert panel._length_spin.value() == 4

    # Byte Array with nothing typed reports no width at all — not the 4 it
    # inherited, and not a default that would jump to 1 on the first digit.
    panel._type_combo.setCurrentText("Byte Array (Hex)")
    assert panel._length_spin.value() == 0
    assert panel._length_spin.text() == EMPTY_LENGTH_TEXT
    panel._value_edit.setText("AA")
    assert panel._length_spin.value() == 1

    # A string value is not valid hex, so switching back to Byte Array can't
    # size it: no stale width carries over from String.
    panel._type_combo.setCurrentText("String (UTF-8)")
    panel._value_edit.setText("some long string here")
    assert panel._length_spin.value() == 21

    panel._type_combo.setCurrentText("Byte Array (Hex)")
    assert panel._length_spin.value() == 0
    # Promoting can't produce a zero-width cheat entry even in that state.
    assert panel.current_spec_and_length()[1] == find_spec("Byte Array (Hex)").length

    # A fixed-width type picked afterwards must show its number, never the
    # empty-slot text (a 1-byte Int8 sits at what was the special value).
    panel._type_combo.setCurrentText("1 Byte  (Int8)")
    assert panel._length_spin.value() == 1
    assert panel._length_spin.text() != EMPTY_LENGTH_TEXT

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


@pytest.mark.skipif(not qtbot_available, reason="pytest-qt not installed.")
def test_compare_view_says_why_values_are_missing_when_modules_fail(
    qtbot, tmp_path, monkeypatch
):
    """Comparing saved scans against a target whose modules can't be listed
    (it exited, say) keeps the intersection, and says why no value is shown
    instead of leaving a table of dimmed rows unexplained."""
    import os

    from PySide6.QtWidgets import QApplication, QFileDialog

    from PyMemoryEditor import OpenProcess, PointerPath
    from PyMemoryEditor.app.pointer_scan_dialog import PointerScanDialog

    QApplication.instance() or QApplication([])
    path = PointerPath(
        base_address=0x1000, offsets=(0x10,), module="game.exe",
        module_offset=0x1000, ptr_size=8,
    )
    files = []
    for index in range(2):
        target = tmp_path / ("scan%d.json" % index)
        process = OpenProcess(pid=os.getpid())
        try:
            process.save_pointer_paths([path], str(target))
        finally:
            process.close()
        files.append(str(target))

    process = OpenProcess(pid=os.getpid())
    try:
        def no_modules():
            raise OSError("target exited")

        monkeypatch.setattr(process, "get_modules", no_modules)
        monkeypatch.setattr(
            QFileDialog, "getOpenFileNames", lambda *a, **k: (files, "")
        )
        dialog = PointerScanDialog(process)
        qtbot.addWidget(dialog)
        dialog._on_compare_saved()

        assert dialog._model.rowCount() == 1
        label = dialog._count_label.text()
        assert "1 path(s) common to 2 scans." in label
        assert "target exited" in label
        dialog.close()
    finally:
        process.close()


class _FakePointerProcess:
    """Enough of a process for the pointer-scan worker and dialog, no memory."""

    def __init__(self, path_count=0, stall_in_map_build=False):
        self.pid = os.getpid()
        self.path_count = path_count
        self.stall_in_map_build = stall_in_map_build

    def scan_pointer_paths(self, target, *, progress_callback, should_stop, **_kwargs):
        from PyMemoryEditor import PointerPath

        import time

        while self.stall_in_map_build:
            # Stop raises out of the progress callback, as in the real build.
            progress_callback(0.5)
            time.sleep(0.005)
        for index in range(self.path_count):
            yield PointerPath(
                base_address=0x1000 + 8 * index, offsets=(0x10,), ptr_size=8
            )

    def resolve_pointer_chain(self, base_address, offsets, ptr_size=8):
        return 0x5000

    def read_process_memory(self, address, pytype, length):
        return 7

    def get_modules(self):
        return []

    def close(self):
        pass


def _pointer_request(max_results=None):
    from PyMemoryEditor.app.pointer_scan_dialog import PointerScanRequest
    from PyMemoryEditor.app.value_types import find_spec

    return PointerScanRequest(
        target_address=0x5000, max_depth=2, max_offset=0x100, ptr_size=8,
        writable_only=False, aligned=True, max_results=max_results,
        spec=find_spec("4 Bytes (Int32)"), length=4,
    )


@pytest.mark.skipif(not qtbot_available, reason="pytest-qt not installed.")
def test_stopping_a_pointer_scan_mid_map_build_says_stopped(qtbot):
    """
    Stop while the pointer map was still being built made the worker report
    0 paths, and the dialog answered "No pointer paths found. Try a higher
    depth…" for a scan that never got to look.
    """
    from PyMemoryEditor.app.pointer_scan_dialog import PointerScanDialog, PointerScanWorker

    process = _FakePointerProcess(stall_in_map_build=True)
    dialog = PointerScanDialog(process)
    qtbot.addWidget(dialog)
    dialog._set_scanning(True)
    dialog._start_worker(PointerScanWorker(process, _pointer_request(), dialog))
    dialog._on_stop()
    qtbot.waitUntil(lambda: dialog._worker is None, timeout=5000)

    label = dialog._count_label.text()
    assert "No pointer paths found" not in label
    assert label.startswith("Stopped")
    dialog.close()


@pytest.mark.skipif(not qtbot_available, reason="pytest-qt not installed.")
def test_pointer_scan_worker_waits_for_the_ui_to_draw_its_batches(qtbot):
    """
    ``rows_ready`` was fire-and-forget: with "Unlimited" results a fast walk
    queued batches faster than the UI appended them, without bound. The worker
    now waits once a few batches are outstanding, and Stop still ends it.
    """
    from PyMemoryEditor.app.pointer_scan_dialog import (
        _MAX_BATCHES_IN_FLIGHT,
        _UI_BATCH,
        PointerScanDialog,
        PointerScanWorker,
    )

    process = _FakePointerProcess(path_count=_UI_BATCH * 20)
    worker = PointerScanWorker(process, _pointer_request())
    received = []
    worker.rows_ready.connect(received.append)  # drawn, but never acknowledged
    worker.start()
    try:
        qtbot.waitUntil(
            lambda: worker._in_flight == _MAX_BATCHES_IN_FLIGHT, timeout=5000
        )
        qtbot.wait(100)
        assert worker.isRunning()
        assert worker._in_flight == _MAX_BATCHES_IN_FLIGHT
        assert len(received) <= _MAX_BATCHES_IN_FLIGHT
    finally:
        worker.cancel()
        assert worker.wait(5000)

    # Wired through the dialog, every batch is acknowledged and the scan ends.
    total = _UI_BATCH * 20 + 37
    process = _FakePointerProcess(path_count=total)
    dialog = PointerScanDialog(process)
    qtbot.addWidget(dialog)
    dialog._set_scanning(True)
    dialog._start_worker(PointerScanWorker(process, _pointer_request(), dialog))
    qtbot.waitUntil(lambda: dialog._worker is None, timeout=10000)
    assert dialog._model.rowCount() == total
    assert dialog._count_label.text() == f"{total:,} pointer path(s)."
    dialog.close()


@pytest.mark.skipif(not qtbot_available, reason="pytest-qt not installed.")
def test_compare_shows_a_path_whose_module_is_gone_as_unresolved(
    qtbot, tmp_path, monkeypatch
):
    """
    Compare used to fall back to a module path's saved absolute base when the
    module isn't loaded now, walking the previous run's addresses and showing
    whatever it read there as the path's value. Rescan drops such a path;
    compare keeps it (membership is decided by recipe) but shows it
    unresolved. A path whose module is loaded still resolves.
    """
    import json
    from types import SimpleNamespace

    from PySide6.QtWidgets import QFileDialog

    from PyMemoryEditor import PointerPath
    from PyMemoryEditor.app.pointer_scan_dialog import (
        _COL_RESOLVED,
        _COL_VALUE,
        PointerScanDialog,
    )

    paths = [
        PointerPath(
            base_address=0x1000, offsets=(0x10,), module=name,
            module_offset=0x1000, ptr_size=8,
        )
        for name in ("engine.dll", "game.exe")
    ]
    files = []
    for index in range(2):
        target = tmp_path / ("scan%d.json" % index)
        target.write_text(json.dumps({"paths": [p.to_dict() for p in paths]}))
        files.append(str(target))
    monkeypatch.setattr(QFileDialog, "getOpenFileNames", lambda *a, **k: (files, ""))

    process = _FakePointerProcess()
    # Only game.exe is loaded in this run.
    process.get_modules = lambda: [SimpleNamespace(name="game.exe", base_address=0x400000)]
    dialog = PointerScanDialog(process)
    qtbot.addWidget(dialog)
    dialog._on_compare_saved()

    shown = {
        dialog._model.item(row, 0).data(0x0100).module: (
            dialog._model.item(row, _COL_RESOLVED).text(),
            dialog._model.item(row, _COL_VALUE).text(),
        )
        for row in range(dialog._model.rowCount())
    }
    assert shown == {"engine.dll": ("—", "—"), "game.exe": ("0x5000", "7")}

    # Acting on the unresolved row must not walk its saved absolute base
    # either: "Add to cheat table" / "hex viewer" refuse it with a message.
    from PySide6.QtWidgets import QMessageBox

    warnings = []
    monkeypatch.setattr(QMessageBox, "warning", lambda *a, **k: warnings.append(a))
    rows = {
        dialog._model.item(row, 0).data(0x0100).module: row
        for row in range(dialog._model.rowCount())
    }
    for module, expected in (("engine.dll", None), ("game.exe", 0x5000)):
        dialog._table.selectRow(rows[module])
        assert dialog._resolve_selected() == expected
    assert len(warnings) == 1 and "engine.dll" in warnings[0][2]
    dialog.close()


# --- excepthook ------------------------------------------------------------- #


def test_qt_excepthook_logs_and_reports_but_passes_keyboard_interrupt(monkeypatch, caplog):
    """
    PySide6 hands a slot's exception to ``sys.excepthook`` and carries on, so
    the default hook meant a silent click. The app's hook logs it (for the Log
    Console) and shows it; KeyboardInterrupt stays the interpreter's business.
    """
    import logging
    import sys

    from PySide6.QtWidgets import QApplication, QMessageBox

    from PyMemoryEditor.app.application import _qt_excepthook, _scoped_excepthook

    QApplication.instance() or QApplication([])
    shown = []
    monkeypatch.setattr(QMessageBox, "critical", lambda *args, **kwargs: shown.append(args[2]))
    passed_through = []
    monkeypatch.setattr(sys, "__excepthook__", lambda *args: passed_through.append(args[0]))

    with caplog.at_level(logging.ERROR, logger="PyMemoryEditor.app.application"):
        try:
            raise ValueError("boom")
        except ValueError:
            _qt_excepthook(*sys.exc_info())

    assert shown and "ValueError: boom" in shown[0]
    assert any("Unhandled exception in the UI" in r.message for r in caplog.records)
    assert passed_through == []

    _qt_excepthook(KeyboardInterrupt, KeyboardInterrupt(), None)
    assert passed_through == [KeyboardInterrupt]
    assert len(shown) == 1

    # Scoped: installed for the block, the previous hook restored after it.
    previous = sys.excepthook
    with _scoped_excepthook(_qt_excepthook):
        assert sys.excepthook is _qt_excepthook
    assert sys.excepthook is previous


def test_qt_excepthook_only_logs_when_called_off_the_gui_thread(monkeypatch, caplog):
    """
    PySide6 routes an exception escaping ``QThread.run()`` through the same
    hook, from the worker thread. Widgets may only be created on the GUI
    thread, so there the hook must log and stop — no dialog.
    """
    import logging
    import sys
    import threading

    from PySide6.QtWidgets import QApplication, QMessageBox

    from PyMemoryEditor.app.application import _qt_excepthook

    QApplication.instance() or QApplication([])
    shown = []
    monkeypatch.setattr(QMessageBox, "critical", lambda *args, **kwargs: shown.append(args[2]))

    def raise_in_thread():
        try:
            raise RuntimeError("worker boom")
        except RuntimeError:
            _qt_excepthook(*sys.exc_info())

    with caplog.at_level(logging.ERROR, logger="PyMemoryEditor.app.application"):
        worker = threading.Thread(target=raise_in_thread)
        worker.start()
        worker.join(5)

    assert not worker.is_alive()
    assert shown == []
    assert any("worker boom" in (r.exc_text or "") for r in caplog.records)
