# -*- coding: utf-8 -*-
"""
Pointer-chain dialog — exposes ``process.resolve_pointer_chain()``.

It resolves a multi-level pointer — a static base plus a series of bracketed
offsets — written like::

    "game.exe" + 0x10F4F4 -> [+0x0] -> [+0x158]

This dialog asks for:

* a **base address** in hex,
* the **list of offsets** (the bracketed steps, comma-separated, hex),
* the **pointer size** (4 for 32-bit targets, 8 for 64-bit).

Then it walks the chain, surfaces the final address, reads the value with
the chosen value type, and offers an *"Add to cheat table"* shortcut that
emits a signal the main window picks up — so the resolved address survives
into the regular freeze/refresh loop.

Same construction shape as the existing Memory Map / Hex Viewer dialogs
(small, self-contained, no background worker because the chain walk is
already fast).
"""
import logging
from typing import List, Optional, Tuple

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QFont, QGuiApplication
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QSpinBox,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from PyMemoryEditor import AbstractProcess

from ._widgets import parse_hex_address
from .value_types import VALUE_TYPES, ValueTypeSpec, find_spec


# Child of "PyMemoryEditor" — surfaced by the Log Console via propagation.
_LOG = logging.getLogger(__name__)


class _OffsetField(QWidget):
    """One slot in the offsets chain — visually ``[+ <hex> ]``.

    A pointer walk is written ``[+0x10] -> [+0x20]``; we mirror that with a
    label-input-label triple per offset so the "list of offsets" reads as a
    chain instead of as a free-form text field.
    The trailing ``×`` removes this field; the parent dialog hides the
    button when only one slot remains.
    """

    removed = Signal(object)  # self

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(2)

        prefix = QLabel("[+")
        prefix.setObjectName("hint")
        layout.addWidget(prefix)

        self.edit = QLineEdit()
        self.edit.setPlaceholderText("0")
        self.edit.setFixedWidth(80)
        self.edit.setFont(QFont("Menlo, Consolas, Courier New", 10))
        layout.addWidget(self.edit)

        suffix = QLabel("]")
        suffix.setObjectName("hint")
        layout.addWidget(suffix)

        self.remove_btn = QToolButton(self)
        self.remove_btn.setText("×")
        self.remove_btn.setToolTip("Remove this offset")
        self.remove_btn.setFixedSize(20, 20)
        self.remove_btn.clicked.connect(lambda: self.removed.emit(self))
        layout.addWidget(self.remove_btn)

    def text(self) -> str:
        return self.edit.text().strip()


class PointerChainDialog(QDialog):
    """Walk a multi-level pointer chain and surface the final address."""

    # qulonglong: addresses regularly exceed Qt's signed-32-bit default.
    add_to_cheat_table = Signal(
        "qulonglong", str, int
    )  # (resolved_address, spec_label, length)

    def __init__(self, process: AbstractProcess, parent=None):
        super().__init__(parent)
        self._process = process
        self._resolved_address: Optional[int] = None

        self.setWindowTitle(f"Resolve Pointer Chain — PID {process.pid}")
        self.resize(640, 460)

        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(10)

        header = QLabel(
            "<span style='font-size:16px;font-weight:700;'>Resolve Pointer Chain</span>"
        )
        header.setTextFormat(Qt.RichText)
        layout.addWidget(header)

        hint = QLabel(
            "Enter a pointer chain. The base can be an absolute hex address, or "
            "a module-relative base written <b>\"module\"+0xoffset</b> "
            "(e.g. from a pointer-scan path) — it survives ASLR because the "
            "module's current load base is looked up for you."
        )
        hint.setTextFormat(Qt.RichText)
        hint.setObjectName("hint")
        hint.setWordWrap(True)
        layout.addWidget(hint)

        form = QFormLayout()
        form.setHorizontalSpacing(10)
        form.setVerticalSpacing(8)

        self._base_edit = QLineEdit()
        self._base_edit.setPlaceholderText(
            'e.g. 0x14010F4F4  or  "game.exe"+0x10F4F4'
        )
        form.addRow("Base address:", self._base_edit)

        # Optional convenience: paste the raw module base in "Base address" (e.g.
        # copied from the Modules window) and the static module_offset here — the
        # resolver adds them. Equivalent to the "module"+0xoffset base syntax.
        self._module_offset_edit = QLineEdit()
        self._module_offset_edit.setPlaceholderText(
            "optional — added to base (e.g. 0x4A0C68 from a pointer-scan path)"
        )
        self._module_offset_edit.setFont(QFont("Menlo, Consolas, Courier New", 10))
        form.addRow("Module offset:", self._module_offset_edit)

        # Offsets row — a chain of "[+ hex ]" slots with a
        # trailing "+" button to add another hop. Wrapped in a horizontal
        # scroll area so deep chains (10+ levels) don't blow up the dialog
        # width.
        self._offset_fields: List[_OffsetField] = []

        offsets_container = QWidget()
        self._offsets_row = QHBoxLayout(offsets_container)
        self._offsets_row.setContentsMargins(0, 0, 0, 0)
        self._offsets_row.setSpacing(4)

        # The "+" button lives in the layout and stays at the right end; we
        # insert new fields just *before* it via insertWidget(index-1, …).
        self._add_offset_btn = QToolButton()
        self._add_offset_btn.setText("+")
        self._add_offset_btn.setToolTip("Add another offset (one more hop in the chain)")
        self._add_offset_btn.setFixedSize(28, 24)
        self._add_offset_btn.clicked.connect(lambda: self._add_offset_field())
        self._offsets_row.addWidget(self._add_offset_btn)
        self._offsets_row.addStretch(1)

        offsets_scroll = QScrollArea()
        offsets_scroll.setWidget(offsets_container)
        offsets_scroll.setWidgetResizable(True)
        offsets_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        offsets_scroll.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        offsets_scroll.setFrameShape(QScrollArea.NoFrame)
        offsets_scroll.setFixedHeight(40)
        form.addRow("Offsets:", offsets_scroll)

        # Start with a single empty slot so the dialog isn't blank.
        self._add_offset_field()

        self._ptr_size_combo = QComboBox()
        self._ptr_size_combo.addItem("8 bytes (64-bit)", 8)
        self._ptr_size_combo.addItem("4 bytes (32-bit)", 4)
        form.addRow("Pointer size:", self._ptr_size_combo)

        # By default the chain assumes ``base`` is a *static slot* in the
        # executable that holds a pointer (so we dereference once before
        # walking offsets). Users who pass a *direct* address (e.g. from
        # the Memory Map or a fresh scan) want ``base`` to be the final
        # address itself — offsets in that case are struct-field offsets,
        # added without any extra dereference.
        self._deref_check = QCheckBox(
            "Base is a pointer (dereference it, then walk offsets)"
        )
        self._deref_check.setChecked(True)
        self._deref_check.setToolTip(
            "Checked: base address holds a pointer; the resolver reads that "
            "pointer, then dereferences again on each offset.\n\n"
            "Unchecked: base is the final address itself. Offsets are added "
            "without dereferencing — useful when you pasted an address from "
            "the Memory Map or want a struct field at base+offset."
        )
        form.addRow("", self._deref_check)

        self._value_type_combo = QComboBox()
        for spec in VALUE_TYPES:
            self._value_type_combo.addItem(spec.label)
        form.addRow("Read value as:", self._value_type_combo)

        self._length_spin = QSpinBox()
        self._length_spin.setRange(1, 1024)
        self._length_spin.setValue(4)
        self._length_spin.setSuffix("  bytes")
        self._value_type_combo.currentTextChanged.connect(self._on_value_type_changed)
        form.addRow("Length:", self._length_spin)

        layout.addLayout(form)

        # The primary/secondary/danger QSS rules add `padding: 7px 14px;
        # min-height: 20px`, making those buttons taller than a plain
        # QPushButton (5px 12px). Apply the same padding to the neutral
        # buttons so the whole row lines up at the Resolve button's height.
        _equal_height = "padding: 7px 14px; min-height: 20px;"

        button_row = QHBoxLayout()
        self._resolve_btn = QPushButton("Resolve")
        self._resolve_btn.setObjectName("secondary")
        self._resolve_btn.setDefault(True)
        self._resolve_btn.clicked.connect(self._on_resolve)
        button_row.addWidget(self._resolve_btn)

        self._copy_addr_btn = QPushButton("Copy address")
        self._copy_addr_btn.setStyleSheet(_equal_height)
        self._copy_addr_btn.clicked.connect(self._on_copy_address)
        self._copy_addr_btn.setEnabled(False)
        button_row.addWidget(self._copy_addr_btn)

        self._add_to_cheat_btn = QPushButton("Add to cheat table")
        self._add_to_cheat_btn.setStyleSheet(_equal_height)
        self._add_to_cheat_btn.clicked.connect(self._on_add_to_cheat)
        self._add_to_cheat_btn.setEnabled(False)
        button_row.addWidget(self._add_to_cheat_btn)

        button_row.addStretch(1)

        close_btn = QPushButton("Close")
        close_btn.setStyleSheet(_equal_height)
        close_btn.clicked.connect(self.accept)
        button_row.addWidget(close_btn)
        layout.addLayout(button_row)

        layout.addSpacing(8)

        self._output_label = QLabel("Resolved address: —")
        self._output_label.setObjectName("hint")
        self._output_label.setFont(QFont("Menlo, Consolas, Courier New", 11))
        self._output_label.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse
        )
        layout.addWidget(self._output_label)

        self._value_label = QLabel("Value: —")
        self._value_label.setFont(QFont("Menlo, Consolas, Courier New", 11))
        self._value_label.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse
        )
        layout.addWidget(self._value_label)

        layout.addStretch(1)

        # Sync default spec/length so the spin shows the right value at open.
        self._on_value_type_changed(self._value_type_combo.currentText())

    def _add_offset_field(self) -> _OffsetField:
        """Append a fresh offset slot before the ``+`` button."""
        field = _OffsetField(self)
        field.removed.connect(self._remove_offset_field)
        # Layout order is [field, field, …, "+" btn, stretch]. New entries go
        # in position (count - 2) so they land *before* the "+" button.
        insert_index = max(0, self._offsets_row.count() - 2)
        self._offsets_row.insertWidget(insert_index, field)
        self._offset_fields.append(field)
        field.edit.setFocus()
        self._update_remove_buttons()
        return field

    def _remove_offset_field(self, field: _OffsetField) -> None:
        """Drop ``field`` from the chain — unless it's the only one left."""
        if field not in self._offset_fields:
            return
        if len(self._offset_fields) == 1:
            # Always keep at least one slot so the user has somewhere to type;
            # clearing the input is the closest "remove" we can do here.
            field.edit.clear()
            return
        self._offset_fields.remove(field)
        self._offsets_row.removeWidget(field)
        field.setParent(None)
        field.deleteLater()
        self._update_remove_buttons()

    def _update_remove_buttons(self) -> None:
        """Hide the ``×`` on the only-remaining field so the chain never collapses."""
        only_one = len(self._offset_fields) <= 1
        for field in self._offset_fields:
            field.remove_btn.setVisible(not only_one)

    def _read_offsets(self) -> Optional[List[int]]:
        """Collect non-empty offsets in order; return None if any one is invalid."""
        offsets: List[int] = []
        for field in self._offset_fields:
            text = field.text()
            if not text:
                continue
            parsed = parse_hex_address(text)
            if parsed is None:
                # parse_hex_address only handles full hex addresses with or
                # without ``0x``; try a plain hex int as a fallback for tokens
                # like ``"10"`` that look ambiguous (decimal vs hex). The
                # whole dialog treats offsets as hex.
                try:
                    parsed = int(text, 16)
                except ValueError:
                    return None
            offsets.append(parsed)
        return offsets

    def _on_value_type_changed(self, label: str) -> None:
        spec = find_spec(label)
        if spec is None:
            return
        self._length_spin.setEnabled(spec.accepts_length_override)
        if not spec.accepts_length_override:
            self._length_spin.setValue(spec.length)
        elif spec.pytype is bytes:
            self._length_spin.setValue(max(4, self._length_spin.value()))
        else:
            self._length_spin.setValue(16)

    def _current_spec(self) -> Tuple[ValueTypeSpec, int]:
        spec = find_spec(self._value_type_combo.currentText()) or VALUE_TYPES[0]
        length = self._length_spin.value() if spec.accepts_length_override else spec.length
        return spec, int(length)

    def set_base_address(self, address: int) -> None:
        """Prefill the Base field with an absolute address (e.g. a module base).

        Clears the Module offset field so the next thing the user types there
        is added to this base from a clean slate.
        """
        self._base_edit.setText("0x%X" % int(address))
        self._module_offset_edit.clear()
        self._base_edit.setFocus()

    def _lookup_module_base(self, name: str) -> Optional[int]:
        """Current load base of the module named ``name`` (case-insensitive)."""
        name_lower = name.lower()
        for module in self._process.get_modules():
            if module.name.lower() == name_lower:
                return module.base_address
        return None

    def _resolve_base(self, text: str) -> Optional[int]:
        """
        Parse the Base field into an absolute address.

        Accepts either a plain hex address (``0x14010F4F4``) or Cheat-Engine's
        ``"module"+0xoffset`` form (``"libpython3.12.dylib"+0x4ED3D0``), looking
        the module's current load base up via ``get_modules()`` and adding the
        offset — so a saved pointer-scan path (module + module_offset) can be
        pasted straight in and resolves correctly despite ASLR. Shows a specific
        warning and returns ``None`` on failure.
        """
        text = text.strip()

        if "+" in text:
            name_part, _, offset_part = text.partition("+")
            module_name = name_part.strip().strip('"').strip("'").strip()
            offset = parse_hex_address(offset_part)
            if offset is None:
                try:
                    offset = int(offset_part.strip(), 16)
                except ValueError:
                    QMessageBox.warning(
                        self,
                        "Resolve",
                        "The offset after '+' must be hex (e.g. \"game.exe\"+0x10F4F4).",
                    )
                    return None
            module_base = self._lookup_module_base(module_name)
            if module_base is None:
                QMessageBox.warning(
                    self,
                    "Resolve",
                    f"Module {module_name!r} is not loaded in this process.\n\n"
                    "Open Tools → Modules to see the exact names available.",
                )
                return None
            return module_base + offset

        base = parse_hex_address(text)
        if base is None:
            QMessageBox.warning(
                self,
                "Resolve",
                'Base must be hex (0x14010F4F4) or "module"+0xoffset '
                '(e.g. "game.exe"+0x10F4F4).',
            )
        return base

    def _on_resolve(self) -> None:
        base_text = self._base_edit.text().strip()
        if not base_text:
            QMessageBox.warning(self, "Resolve", "Enter a base address first.")
            return

        base = self._resolve_base(base_text)
        if base is None:
            return  # _resolve_base already explained why

        # Optional module-offset field: added to the base *before* any
        # dereference (it locates the static slot — it is NOT a chain offset).
        module_offset_text = self._module_offset_edit.text().strip()
        if module_offset_text:
            module_offset = parse_hex_address(module_offset_text)
            if module_offset is None:
                try:
                    module_offset = int(module_offset_text, 16)
                except ValueError:
                    QMessageBox.warning(
                        self,
                        "Resolve",
                        "Module offset must be hex (e.g. 0x4A0C68). Leave it "
                        "empty if your base address already includes it.",
                    )
                    return
            base += module_offset

        offsets = self._read_offsets()
        if offsets is None:
            QMessageBox.warning(
                self,
                "Resolve",
                "Every offset must be hex (e.g. 0x10, 158, 0xC8). "
                "Leave a slot empty to skip it, or click × to remove it.",
            )
            return

        ptr_size = int(self._ptr_size_combo.currentData())
        dereference = self._deref_check.isChecked()

        if dereference:
            try:
                resolved = self._process.resolve_pointer_chain(
                    base, offsets, ptr_size=ptr_size
                )
            except Exception as exc:  # noqa: BLE001
                QMessageBox.critical(
                    self,
                    "Resolve",
                    "Could not walk the chain — typically one of the "
                    "intermediate pointers is invalid. If the base is already "
                    "the final address (e.g. from the Memory Map), uncheck "
                    "\"Base is a pointer\".\n\n"
                    f"{type(exc).__name__}: {exc}",
                )
                _LOG.warning(
                    "Pointer chain resolve failed (base=0x%X, offsets=%s, "
                    "ptr_size=%d): %s: %s",
                    base,
                    offsets,
                    ptr_size,
                    type(exc).__name__,
                    exc,
                )
                self._resolved_address = None
                self._output_label.setText("Resolved address: —")
                self._value_label.setText("Value: —")
                self._copy_addr_btn.setEnabled(False)
                self._add_to_cheat_btn.setEnabled(False)
                return
            hop_summary = f"walked {len(offsets)} hop(s)"
        else:
            # Raw mode: just add the offsets together. No syscalls — the
            # resolver semantics here are "base + sum(offsets)".
            resolved = base + sum(offsets)
            hop_summary = (
                "direct (no dereference)" if not offsets
                else f"base + sum of {len(offsets)} offset(s)"
            )

        self._resolved_address = resolved
        self._output_label.setText(
            f"Resolved address: 0x{resolved:X}  ({hop_summary})"
        )

        spec, length = self._current_spec()
        try:
            value = self._process.read_process_memory(
                resolved, spec.pytype, length
            )
        except Exception as exc:  # noqa: BLE001
            self._value_label.setText(
                f"Value: <read failed: {type(exc).__name__}: {exc}>"
            )
        else:
            try:
                formatted = spec.format(value)
            except Exception:  # noqa: BLE001
                formatted = repr(value)
            self._value_label.setText(f"Value ({spec.label}): {formatted}")

        self._copy_addr_btn.setEnabled(True)
        self._add_to_cheat_btn.setEnabled(True)

    def _on_copy_address(self) -> None:
        if self._resolved_address is None:
            return
        QGuiApplication.clipboard().setText(f"{self._resolved_address:X}")

    def _on_add_to_cheat(self) -> None:
        if self._resolved_address is None:
            return
        spec, length = self._current_spec()
        self.add_to_cheat_table.emit(self._resolved_address, spec.label, length)
