# -*- coding: utf-8 -*-
"""
The left-side scanner panel (Cheat Engine's "Scan" pane).

Inputs:
* primary value (and a second value for "Value Between" / "Not Value Between")
* value type
* scan type
* byte length (fixed per numeric type; derived from the value for str / bytes)
* "writable regions only" toggle (passed to PyMemoryEditor as ``writeable_only``)

Outputs (signals):
* :pysig:`first_scan_requested(ScanRequest)`
* :pysig:`next_scan_requested(ScanRequest)`
* :pysig:`new_scan_requested()` — drop results and unlock the inputs
* :pysig:`update_values_requested(ScanRequest)` — re-read values without filtering
* :pysig:`cancel_requested()`
"""
from typing import Optional

from PySide6.QtCore import Signal
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFormLayout,
    QFrame,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from PyMemoryEditor import ScanTypesEnum

from .scan_types import (
    DELTA_SCAN_TYPES,
    NO_VALUE_SCAN_TYPES,
    NextScanType,
    is_next_scan_type,
)
from .scan_worker import build_scan_request, ScanRequest
from .value_types import parse_value, ValueTypeSpec, VALUE_TYPES, find_spec


# Shown in the (read-only) Length field of String / Byte Array before a value
# has been entered: those types take their width from the value itself, so
# there is genuinely no number to report yet.
EMPTY_LENGTH_TEXT = "—  (set by the value)"


def is_sized_by_value(spec: ValueTypeSpec) -> bool:
    """True for the types whose buffer width comes from the value entered.

    String (UTF-8) and Byte Array (Hex) only. The numeric types have a fixed
    width, an IDA pattern derives one from the pattern, and a regex's Length
    field is a genuine user-set ``byte_length`` — none of them may have their
    width taken from a scan's value.
    """
    return spec.pytype in (str, bytes) and not spec.is_pattern


# The two scan types that take a second value; their width is max(lo, hi).
RANGE_SCAN_TYPES = frozenset(
    (ScanTypesEnum.VALUE_BETWEEN, ScanTypesEnum.NOT_VALUE_BETWEEN)
)


SCAN_TYPE_CHOICES = (
    ("Exact Value", ScanTypesEnum.EXACT_VALUE),
    ("Not Exact Value", ScanTypesEnum.NOT_EXACT_VALUE),
    ("Bigger Than", ScanTypesEnum.BIGGER_THAN),
    ("Smaller Than", ScanTypesEnum.SMALLER_THAN),
    ("Bigger Than or Equal To", ScanTypesEnum.BIGGER_THAN_OR_EXACT_VALUE),
    ("Smaller Than or Equal To", ScanTypesEnum.SMALLER_THAN_OR_EXACT_VALUE),
    ("Value Between", ScanTypesEnum.VALUE_BETWEEN),
    ("Not Value Between", ScanTypesEnum.NOT_VALUE_BETWEEN),
    # App-only "Next Scan" comparisons (current value vs. previous scan).
    ("Increased Value", NextScanType.INCREASED_VALUE),
    ("Increased Value By", NextScanType.INCREASED_VALUE_BY),
    ("Decreased Value", NextScanType.DECREASED_VALUE),
    ("Decreased Value By", NextScanType.DECREASED_VALUE_BY),
    ("Changed Value", NextScanType.CHANGED_VALUE),
    ("Unchanged Value", NextScanType.UNCHANGED_VALUE),
)


class ScannerPanel(QWidget):

    first_scan_requested = Signal(ScanRequest)
    next_scan_requested = Signal(ScanRequest)
    new_scan_requested = Signal()
    update_values_requested = Signal(ScanRequest)
    cancel_requested = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self._has_results = False
        self._busy = False
        self._initial_focus_done = False
        # Width the scan that produced the current results ran at. The no-value
        # comparisons (Increased / Changed / …) must re-read at exactly this
        # width or they compare against a baseline recorded at another one; the
        # Length readout can't stand in, since it tracks whatever value is in
        # the field right now, which the user is free to edit between scans.
        self._last_scan_length: Optional[int] = None
        # Width of a scan that has been dispatched but hasn't landed yet. It is
        # promoted above only when the owner reports results, so a scan that
        # errors out or finds nothing leaves the values on screen described by
        # the width they were actually read at.
        self._pending_scan_length: Optional[int] = None
        self._build_ui()
        self._refresh_buttons()

    def showEvent(self, event) -> None:
        super().showEvent(event)
        # Land the cursor in the Value field the first time the panel appears
        # so the user can type a target value and press Enter without reaching
        # for the mouse. Guarded so restoring/raising the window later doesn't
        # yank focus away from wherever the user put it.
        if not self._initial_focus_done:
            self._initial_focus_done = True
            self._value_edit.setFocus()

    def _on_value_submitted(self) -> None:
        """Enter in a value field runs the scan that's currently valid.

        Mirrors the buttons' enabled state: First Scan before any results
        exist, Next Scan once they do (and neither in pattern mode / while a
        scan is running, where the buttons are disabled).
        """
        if self._first_scan_btn.isEnabled():
            self._on_first_scan()
        elif self._next_scan_btn.isEnabled():
            self._on_next_scan()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        # Small right inset so the group boxes don't sit flush against the
        # outer splitter handle.
        layout.setContentsMargins(0, 0, 4, 0)
        layout.setSpacing(10)

        value_box = QGroupBox("Value")
        value_form = QFormLayout(value_box)
        value_form.setHorizontalSpacing(10)
        value_form.setVerticalSpacing(8)

        self._value_edit = QLineEdit()
        self._value_edit.setPlaceholderText("e.g. 100  or  0x64  or  Hello")
        self._value_edit.returnPressed.connect(self._on_value_submitted)
        # For String (UTF-8) and Byte Array (Hex) the length is dictated by the
        # typed value, so keep the (disabled) length field in sync as the user types.
        self._value_edit.textChanged.connect(self._on_value_text_changed)
        value_form.addRow("Value:", self._value_edit)

        self._second_value_edit = QLineEdit()
        self._second_value_edit.setPlaceholderText("Upper bound (for ranges only)")
        self._second_value_edit.returnPressed.connect(self._on_value_submitted)
        # A range scan sizes with max(lo, hi), so the upper bound moves the
        # readout just as the primary value does.
        self._second_value_edit.textChanged.connect(self._on_value_text_changed)
        self._second_value_label = QLabel("Up to:")
        value_form.addRow(self._second_value_label, self._second_value_edit)
        self._second_value_edit.hide()
        self._second_value_label.hide()

        self._length_spin = QSpinBox()
        self._length_spin.setRange(1, 1024)
        self._length_spin.setValue(4)
        self._length_spin.setSuffix("  bytes")
        value_form.addRow("Length:", self._length_spin)

        layout.addWidget(value_box)

        scan_box = QGroupBox("Scan Settings")
        scan_form = QFormLayout(scan_box)
        scan_form.setHorizontalSpacing(10)
        scan_form.setVerticalSpacing(8)

        self._type_combo = QComboBox()
        for spec in VALUE_TYPES:
            self._type_combo.addItem(spec.label)
        self._type_combo.currentTextChanged.connect(self._on_type_changed)
        scan_form.addRow("Value type:", self._type_combo)

        self._scan_combo = QComboBox()
        for label, _ in SCAN_TYPE_CHOICES:
            self._scan_combo.addItem(label)
        self._scan_combo.currentIndexChanged.connect(self._on_scan_type_changed)
        scan_form.addRow("Scan type:", self._scan_combo)

        self._writable_check = QCheckBox(
            "Writable regions only (skip read-only memory)"
        )
        self._writable_check.setToolTip(
            "Forwards the writeable_only=True flag to PyMemoryEditor — "
            "much faster, and the right default when looking for tunable game values."
        )
        self._writable_check.setChecked(True)
        scan_form.addRow("", self._writable_check)

        self._snapshot_check = QCheckBox("Cache region map between scans")
        self._snapshot_check.setToolTip(
            "After the first scan, reuse the cached snapshot_memory_regions() result "
            "so subsequent scans skip the region-enumeration step."
        )
        self._snapshot_check.setChecked(True)
        scan_form.addRow("", self._snapshot_check)

        layout.addWidget(scan_box)

        buttons_box = QFrame()
        buttons = QVBoxLayout(buttons_box)
        buttons.setContentsMargins(0, 0, 0, 0)
        buttons.setSpacing(6)

        self._first_scan_btn = QPushButton("First Scan")
        self._first_scan_btn.setObjectName("secondary")
        self._first_scan_btn.clicked.connect(self._on_first_scan)
        buttons.addWidget(self._first_scan_btn)

        row = QHBoxLayout()
        self._next_scan_btn = QPushButton("Next Scan")
        self._next_scan_btn.setObjectName("secondary")
        self._next_scan_btn.clicked.connect(self._on_next_scan)
        row.addWidget(self._next_scan_btn)

        self._new_scan_btn = QPushButton("New Scan")
        self._new_scan_btn.setObjectName("danger")
        self._new_scan_btn.clicked.connect(self.new_scan_requested.emit)
        row.addWidget(self._new_scan_btn)
        buttons.addLayout(row)

        self._update_btn = QPushButton("Update Values")
        self._update_btn.clicked.connect(self._on_update_values)
        buttons.addWidget(self._update_btn)

        self._cancel_btn = QPushButton("Cancel scan")
        self._cancel_btn.setObjectName("danger")
        self._cancel_btn.clicked.connect(self.cancel_requested.emit)
        buttons.addWidget(self._cancel_btn)

        layout.addWidget(buttons_box)
        layout.addStretch(1)

        # Sync widget state with the default type/scan-type selection.
        self._on_type_changed(self._type_combo.currentText())
        self._on_scan_type_changed(0)

    def set_has_results(self, has_results: bool) -> None:
        """Report whether the results table currently holds anything.

        Called by the owner once a scan has actually finished, which is what
        makes it the right moment to adopt that scan's width as the baseline.
        """
        self._has_results = has_results
        if has_results:
            if self._pending_scan_length:
                self._last_scan_length = self._pending_scan_length
        else:
            self._last_scan_length = None
        self._pending_scan_length = None
        self._refresh_buttons()

    def set_busy(self, busy: bool) -> None:
        self._busy = busy
        self._refresh_buttons()

    def use_snapshot_cache(self) -> bool:
        return self._snapshot_check.isChecked()

    def _refresh_buttons(self) -> None:
        scanning = self._busy
        spec = find_spec(self._type_combo.currentText())
        is_pattern = bool(spec and spec.is_pattern)

        self._first_scan_btn.setEnabled(not scanning and not self._has_results)
        # "Next Scan" refines by re-checking the value at each address — that
        # concept doesn't apply to a pattern (re-scanning the pattern would
        # just re-emit the same addresses), so we hide that path in AOB mode.
        self._next_scan_btn.setEnabled(
            not scanning and self._has_results and not is_pattern
        )
        self._update_btn.setEnabled(not scanning and self._has_results)
        self._new_scan_btn.setEnabled(self._has_results and not scanning)
        self._cancel_btn.setEnabled(scanning)
        self._type_combo.setEnabled(not scanning and not self._has_results)
        # Scan-type combo is *always* disabled in pattern mode (forced to EXACT).
        self._scan_combo.setEnabled(not scanning and not is_pattern)
        self._writable_check.setEnabled(not scanning and not self._has_results)

    def _on_type_changed(self, label: str) -> None:
        spec = find_spec(label)
        if spec is None:
            return

        is_pattern = spec.is_pattern
        is_regex = spec.is_regex
        sized_by_value = is_sized_by_value(spec)

        # Pattern modes reuse the "Value" line for the pattern and force the
        # scan-type combo to EXACT (Bigger/Smaller/Between don't apply). The
        # IDA form also hides the length (its match width is inferred from the
        # token count), but a *regex* has no inferable width, so its Length
        # field stays enabled and supplies search_by_pattern's byte_length.
        #
        # String (UTF-8) and Byte Array (Hex) lock the length field: the buffer
        # width is the size of the value the user entered (the text's UTF-8 byte
        # length, multi-byte aware / the number of hex bytes), so letting them
        # override it would only allow truncating the value — which the
        # fixed-width ctypes buffer rejects outright — or over-allocating it,
        # which NUL-pads the target and silently searches for "the value
        # followed by zeros". The field stays visible as a read-only readout
        # kept in sync by _sync_value_length / _on_value_text_changed.
        self._length_spin.setEnabled(
            (spec.accepts_length_override and not is_pattern and not sized_by_value)
            or is_regex
        )

        if is_regex:
            self._value_edit.setPlaceholderText(
                "e.g. Player[0-9]+  (text regex, matched against UTF-8 memory)"
            )
        elif is_pattern:
            self._value_edit.setPlaceholderText(
                'e.g. "48 8B ? ? 00 00" (IDA-style hex with ? wildcards)'
            )
        else:
            self._value_edit.setPlaceholderText("e.g. 100  or  0x64  or  Hello")

        # Every type but the value-sized pair owns a real number here, so clear
        # the "no width yet" slot the previous type may have opened (0 would
        # otherwise render as EMPTY_LENGTH_TEXT for e.g. "1 Byte (Int8)").
        if not sized_by_value:
            self._length_spin.setSpecialValueText("")
            self._length_spin.setMinimum(1)

        if is_regex:
            # Length = the regex's max match width in bytes (byte_length); it
            # drives the chunk overlap so a match straddling a chunk boundary is
            # still found. Seed it with the spec's generous default.
            self._length_spin.setMaximum(1024)
            self._length_spin.setValue(spec.length)
            self._length_spin.setSuffix("  bytes  (max match width)")
        elif is_pattern:
            # No meaningful length for an AOB pattern; the scanner derives it.
            self._length_spin.setMaximum(1024)
            self._length_spin.setValue(1)
            self._length_spin.setSuffix("  bytes")
        elif sized_by_value:  # String (UTF-8) / Byte Array (Hex)
            # Length tracks the typed value — raise the ceiling so long strings
            # aren't visually clamped, then mirror the current value's byte size.
            #
            # Until a value has been entered there is no width to report, and
            # the readout is read-only, so the user can't correct a number we
            # invent. Open a 0 slot rendered as EMPTY_LENGTH_TEXT for that
            # state rather than seeding the spec default (which would show
            # "4 bytes" for an empty byte array and then jump to "1 byte" on
            # the first hex digit) or keeping a width the previous type wrote.
            self._length_spin.setMinimum(0)
            self._length_spin.setSpecialValueText(EMPTY_LENGTH_TEXT)
            self._length_spin.setMaximum(2_147_483_647)
            self._length_spin.setSuffix("  bytes")
            self._length_spin.setValue(0)
            self._sync_value_length()
        else:
            self._length_spin.setMaximum(1024)
            self._length_spin.setValue(spec.length)
            self._length_spin.setSuffix("  bytes")

        # Force EXACT_VALUE on pattern mode and disable the scan-type combo
        # (Bigger Than / Smaller Than / Between are meaningless for patterns).
        if is_pattern:
            for index, (_, scan_type) in enumerate(SCAN_TYPE_CHOICES):
                if scan_type is ScanTypesEnum.EXACT_VALUE:
                    self._scan_combo.setCurrentIndex(index)
                    break
            # Ranges + pattern don't mix — make sure the "second value" is
            # hidden if a range type was selected before switching to pattern.
            self._second_value_edit.hide()
            self._second_value_label.hide()
        self._scan_combo.setEnabled(not is_pattern and not self._busy)

        # Re-apply the value-field state for the current scan type now that the
        # value shape changed (e.g. keep the Value field disabled for a
        # no-value comparison, restore its placeholder otherwise).
        self._on_scan_type_changed(self._scan_combo.currentIndex())

        # The pattern/non-pattern flag also drives Next-Scan availability, so
        # let _refresh_buttons re-evaluate now that the type has flipped.
        self._refresh_buttons()

    def _on_value_text_changed(self, text: str) -> None:
        # _sync_value_length ignores the types that own their length field.
        self._sync_value_length(text)

    def _sync_value_length(self, text: Optional[str] = None) -> None:
        """Mirror the byte size of the value text into the length field.

        Matches ``parse_value``'s rules for the two variable-width types so the
        read-only readout shows exactly the buffer width the scan will use: the
        UTF-8 byte length for a string (byte length, not character count) and
        the number of parsed hex bytes for a byte array.

        The readout is exactly what the current value sizes to, and nothing
        else: an empty field, or a half-typed byte array ("00 1"), reports no
        width at all (EMPTY_LENGTH_TEXT) rather than a number no scan would
        use. A range scan sizes with ``max(lo, hi)``, so both bounds count.
        The "Next Scan" comparisons that carry no value of their own don't read
        this field — they refine at ``_last_scan_length``, the width the scan
        holding the current results actually ran at.

        ``text`` is accepted (and ignored) so the method can sit directly on a
        ``textChanged`` signal; the width always comes from reading the fields,
        since either of the two can be the one that sets it.
        """
        del text  # Both fields are read below; see the docstring.
        spec = find_spec(self._type_combo.currentText())
        # Only the value-sized types have a width to mirror; every other type
        # owns the field (a fixed width, or the regex's editable match width)
        # and must not have it overwritten from here.
        if spec is None or not is_sized_by_value(spec):
            return

        texts = [self._value_edit.text()]
        # Read the scan type rather than the widget's visibility: a child of a
        # panel that hasn't been shown yet reports isVisible() False even after
        # setVisible(True), which would silently drop the upper bound.
        _, scan_type = SCAN_TYPE_CHOICES[self._scan_combo.currentIndex()]
        if scan_type in RANGE_SCAN_TYPES:
            texts.append(self._second_value_edit.text())

        length = 0
        for candidate in texts:
            try:
                _, candidate_length = parse_value(spec, candidate)
            except ValueError:
                continue
            length = max(length, candidate_length)

        self._length_spin.setValue(length)

    def _on_scan_type_changed(self, index: int) -> None:
        _, scan_type = SCAN_TYPE_CHOICES[index]
        ranged = scan_type in RANGE_SCAN_TYPES
        self._second_value_edit.setVisible(ranged)
        self._second_value_label.setVisible(ranged)
        # Entering or leaving a range changes which fields size the scan.
        self._sync_value_length()

        # In pattern mode the Value field holds the AOB pattern and the
        # scan-type combo is forced to EXACT, so leave its value field alone.
        spec = find_spec(self._type_combo.currentText())
        if spec is not None and spec.is_pattern:
            return

        # Increased/Decreased/Changed/Unchanged compare against the previous
        # scan and take no target value, so disable the Value field. The *_BY
        # variants keep it enabled to read the delta.
        no_value = scan_type in NO_VALUE_SCAN_TYPES
        self._value_edit.setEnabled(not no_value)
        if no_value:
            self._value_edit.clear()
            self._value_edit.setPlaceholderText("(not used for this scan type)")
        elif scan_type in DELTA_SCAN_TYPES:
            self._value_edit.setPlaceholderText("Amount the value changed by")
        else:
            self._value_edit.setPlaceholderText("e.g. 100  or  0x64  or  Hello")

    def _build_request(self, *, with_value: bool = True) -> Optional[ScanRequest]:
        spec = find_spec(self._type_combo.currentText())
        if spec is None:
            return None

        _, scan_type = SCAN_TYPE_CHOICES[self._scan_combo.currentIndex()]

        # All the assembly rules live in the pure build_scan_request() (unit
        # tested without Qt). The widget keeps only the genuinely-UI parts:
        # reading the fields and turning the ValueError into a message box.
        try:
            return build_scan_request(
                spec,
                scan_type,
                value_text=self._value_edit.text(),
                second_value_text=self._second_value_edit.text(),
                length_spin_value=self._length_spin.value(),
                previous_scan_length=self._last_scan_length,
                writeable_only=self._writable_check.isChecked(),
                with_value=with_value,
            )
        except ValueError as exc:
            title = "Invalid pattern" if spec.is_pattern else "Invalid value"
            QMessageBox.warning(self, title, str(exc))
            return None

    def _on_first_scan(self) -> None:
        _, scan_type = SCAN_TYPE_CHOICES[self._scan_combo.currentIndex()]
        if is_next_scan_type(scan_type):
            QMessageBox.information(
                self,
                "First Scan",
                "Increased / Decreased / Changed / Unchanged compare against a "
                "previous scan, so they only work as a Next Scan. Run a First "
                "Scan with another comparison (e.g. Exact Value) first, then "
                "switch to one of these and press Next Scan.",
            )
            return
        request = self._build_request()
        if request is not None:
            self._pending_scan_length = request.length
            self.first_scan_requested.emit(request)

    def _on_next_scan(self) -> None:
        request = self._build_request()
        if request is not None:
            # The refine rewrites every kept value at this width, so it becomes
            # the baseline the next no-value comparison has to match — once it
            # has actually run.
            self._pending_scan_length = request.length
            self.next_scan_requested.emit(request)

    def _on_update_values(self) -> None:
        # A read-only refresh of the rows already on screen. RefineScanWorker
        # applies no comparison when filter_only is False, so this needs no
        # target value — and must not parse one: the Value box may be empty
        # (a no-value scan type clears it outright), which would abort the
        # refresh with "Invalid value" instead of refreshing. It re-reads at
        # the width the rows were scanned at and leaves the baseline alone.
        spec, length = self.current_spec_and_length()
        self.update_values_requested.emit(
            ScanRequest(
                spec=spec,
                length=length,
                scan_type=ScanTypesEnum.EXACT_VALUE,
                value=None,
                writeable_only=self._writable_check.isChecked(),
            )
        )

    def current_spec_and_length(self):
        """Return the active (spec, length) pair for the Promote-to-Cheat-Table path."""
        spec = find_spec(self._type_combo.currentText())
        if spec is None:
            spec = VALUE_TYPES[0]
        # An IDA pattern has no Length field and a spec length of 0 (the scanner
        # derives the width from the pattern), so a promoted AOB hit would get a
        # zero-byte buffer that the cheat table then re-reads as empty on every
        # poll tick. Measure the pattern instead — one token is one byte.
        if spec.is_pattern and not spec.is_regex:
            return spec, self._pattern_byte_length()

        # The rows being promoted were read at the width their scan ran at, so
        # that is the width the cheat entry has to keep. The Length readout
        # can't stand in: it follows the Value box, which a no-value scan type
        # clears outright (a 4-byte "olá" scan would promote at the spec's 16,
        # and the entry would read 12 bytes of neighbouring memory into the
        # cell on every poll tick).
        if is_sized_by_value(spec) and self._last_scan_length:
            return spec, self._last_scan_length

        length = (
            self._length_spin.value() if spec.accepts_length_override else spec.length
        )
        # No scan has run yet and no value is entered (readout 0): a cheat entry
        # can't have a zero-width buffer, so the spec default stands in.
        return spec, int(length) or spec.length

    def _pattern_byte_length(self) -> int:
        """Width of one match of the AOB pattern currently in the Value field."""
        from PyMemoryEditor.util.pattern import compile_pattern

        try:
            return max(1, compile_pattern(self._value_edit.text().strip())[1])
        except ValueError:
            # The results being promoted came from a pattern that compiled, so
            # this only happens if the field was edited afterwards. One byte is
            # a harmless entry the user can widen from the cheat table.
            return 1
