# -*- coding: utf-8 -*-
"""
The left-side scanner panel (Cheat Engine's "Scan" pane).

Inputs:
* primary value (and a second value for "Value Between" / "Not Value Between")
* value type
* scan type
* explicit byte length for str / bytes
* "writable regions only" toggle (passed to PyMemoryEditor as ``writeable_only``)

Outputs (signals):
* :pysig:`first_scan_requested(ScanRequest)`
* :pysig:`next_scan_requested(ScanRequest)`
* :pysig:`new_scan_requested()` — drop results and unlock the inputs
* :pysig:`update_values_requested(ScanRequest)` — re-read values without filtering
* :pysig:`cancel_requested()`
"""
from typing import Any, Optional

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

from .scan_worker import ScanRequest
from .value_types import VALUE_TYPES, find_spec, parse_value


SCAN_TYPE_CHOICES = (
    ("Exact Value", ScanTypesEnum.EXACT_VALUE),
    ("Not Exact Value", ScanTypesEnum.NOT_EXACT_VALUE),
    ("Bigger Than", ScanTypesEnum.BIGGER_THAN),
    ("Smaller Than", ScanTypesEnum.SMALLER_THAN),
    ("Bigger Than or Equal To", ScanTypesEnum.BIGGER_THAN_OR_EXACT_VALUE),
    ("Smaller Than or Equal To", ScanTypesEnum.SMALLER_THAN_OR_EXACT_VALUE),
    ("Value Between", ScanTypesEnum.VALUE_BETWEEN),
    ("Not Value Between", ScanTypesEnum.NOT_VALUE_BETWEEN),
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
        self._build_ui()
        self._refresh_buttons()

    # ------------------------------------------------------------------ UI

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        # Small right inset so the group boxes don't sit flush against the
        # outer splitter handle.
        layout.setContentsMargins(0, 0, 4, 0)
        layout.setSpacing(10)

        # -- Value group ---------------------------------------------------
        value_box = QGroupBox("Value")
        value_form = QFormLayout(value_box)
        value_form.setHorizontalSpacing(10)
        value_form.setVerticalSpacing(8)

        self._value_edit = QLineEdit()
        self._value_edit.setPlaceholderText("e.g. 100  or  0x64  or  Hello")
        value_form.addRow("Value:", self._value_edit)

        self._second_value_edit = QLineEdit()
        self._second_value_edit.setPlaceholderText("Upper bound (for ranges only)")
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

        # -- Scan settings group ------------------------------------------
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

        # -- Action buttons -----------------------------------------------
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

    # ----------------------------------------------------------- state

    def set_has_results(self, has_results: bool) -> None:
        self._has_results = has_results
        self._refresh_buttons()

    def set_busy(self, busy: bool) -> None:
        self._busy = busy
        self._refresh_buttons()

    def use_snapshot_cache(self) -> bool:
        return self._snapshot_check.isChecked()

    def _refresh_buttons(self) -> None:
        scanning = self._busy
        self._first_scan_btn.setEnabled(not scanning and not self._has_results)
        self._next_scan_btn.setEnabled(not scanning and self._has_results)
        self._update_btn.setEnabled(not scanning and self._has_results)
        self._new_scan_btn.setEnabled(self._has_results and not scanning)
        self._cancel_btn.setEnabled(scanning)
        self._type_combo.setEnabled(not scanning and not self._has_results)
        self._scan_combo.setEnabled(not scanning)
        self._writable_check.setEnabled(not scanning and not self._has_results)

    # ----------------------------------------------------------- events

    def _on_type_changed(self, label: str) -> None:
        spec = find_spec(label)
        if spec is None:
            return
        self._length_spin.setEnabled(spec.accepts_length_override)
        if spec.accepts_length_override:
            if spec.pytype is bytes:
                self._length_spin.setValue(max(4, self._length_spin.value()))
                self._length_spin.setSuffix("  bytes")
            else:
                self._length_spin.setValue(16)
                self._length_spin.setSuffix("  chars")
        else:
            self._length_spin.setValue(spec.length)
            self._length_spin.setSuffix("  bytes")

    def _on_scan_type_changed(self, index: int) -> None:
        _, scan_type = SCAN_TYPE_CHOICES[index]
        ranged = scan_type in (
            ScanTypesEnum.VALUE_BETWEEN,
            ScanTypesEnum.NOT_VALUE_BETWEEN,
        )
        self._second_value_edit.setVisible(ranged)
        self._second_value_label.setVisible(ranged)

    # ----------------------------------------------------------- request builders

    def _build_request(self, *, with_value: bool = True) -> Optional[ScanRequest]:
        spec = find_spec(self._type_combo.currentText())
        if spec is None:
            return None

        _, scan_type = SCAN_TYPE_CHOICES[self._scan_combo.currentIndex()]

        length_override = (
            self._length_spin.value() if spec.accepts_length_override else None
        )

        value: Any
        try:
            if scan_type in (
                ScanTypesEnum.VALUE_BETWEEN,
                ScanTypesEnum.NOT_VALUE_BETWEEN,
            ):
                lo, lo_len = parse_value(spec, self._value_edit.text(), length_override)
                hi, hi_len = parse_value(
                    spec, self._second_value_edit.text(), length_override
                )
                length = max(lo_len, hi_len)
                value = (lo, hi)
            else:
                value, length = parse_value(
                    spec, self._value_edit.text(), length_override
                )
        except ValueError as exc:
            QMessageBox.warning(self, "Invalid value", str(exc))
            return None

        if not with_value:
            value = None  # Used by callers that only need spec/length/scan_type.

        return ScanRequest(
            spec=spec,
            length=int(length),
            scan_type=scan_type,
            value=value,
            writeable_only=self._writable_check.isChecked(),
        )

    def _on_first_scan(self) -> None:
        request = self._build_request()
        if request is not None:
            self.first_scan_requested.emit(request)

    def _on_next_scan(self) -> None:
        request = self._build_request()
        if request is not None:
            self.next_scan_requested.emit(request)

    def _on_update_values(self) -> None:
        request = self._build_request()
        if request is not None:
            self.update_values_requested.emit(request)

    # ----------------------------------------------------------- public helpers

    def current_spec_and_length(self):
        """Return the active (spec, length) pair for the Promote-to-Cheat-Table path."""
        spec = find_spec(self._type_combo.currentText())
        if spec is None:
            spec = VALUE_TYPES[0]
        length = (
            self._length_spin.value() if spec.accepts_length_override else spec.length
        )
        return spec, int(length)
