# -*- coding: utf-8 -*-
"""
Background threads that drive the heavy PyMemoryEditor calls.

Two workers live here:

* :class:`FirstScanWorker` — wraps ``search_by_value`` and
  ``search_by_value_between`` for the very first scan over the entire address
  space.
* :class:`RefineScanWorker` — wraps ``search_by_addresses`` and discards
  addresses whose current value no longer matches the user's filter (this is
  Cheat Engine's "Next Scan").

Both expose ``progress`` / ``found`` / ``finished`` signals so the UI never
blocks on a long scan.
"""
import logging
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, cast

from PySide6.QtCore import QThread, Signal

from PyMemoryEditor import AbstractProcess, ScanTypesEnum

from .scan_types import NextScanType, ScanType
from .value_types import ValueTypeSpec


_LOG = logging.getLogger(__name__)


# Map of ScanTypesEnum → comparison used by the refine step. These compare the
# freshly-read value (cur) against the user-supplied target (exp).
COMPARATORS = {
    ScanTypesEnum.EXACT_VALUE: lambda cur, exp: cur == exp,
    ScanTypesEnum.NOT_EXACT_VALUE: lambda cur, exp: cur != exp,
    ScanTypesEnum.BIGGER_THAN: lambda cur, exp: cur > exp,
    ScanTypesEnum.SMALLER_THAN: lambda cur, exp: cur < exp,
    ScanTypesEnum.BIGGER_THAN_OR_EXACT_VALUE: lambda cur, exp: cur >= exp,
    ScanTypesEnum.SMALLER_THAN_OR_EXACT_VALUE: lambda cur, exp: cur <= exp,
    ScanTypesEnum.VALUE_BETWEEN: lambda cur, exp: exp[0] <= cur <= exp[1],
    ScanTypesEnum.NOT_VALUE_BETWEEN: lambda cur, exp: cur < exp[0] or cur > exp[1],
}

# Cheat Engine's "Next Scan" comparisons (app-only — see scan_types.py). These
# compare the freshly-read value (cur) against the value recorded at that
# address by the previous scan (prev). ``exp`` carries the delta for the *_BY
# variants and is ignored otherwise.
PREVIOUS_COMPARATORS = {
    NextScanType.INCREASED_VALUE: lambda cur, prev, exp: cur > prev,
    NextScanType.INCREASED_VALUE_BY: lambda cur, prev, exp: cur == prev + exp,
    NextScanType.DECREASED_VALUE: lambda cur, prev, exp: cur < prev,
    NextScanType.DECREASED_VALUE_BY: lambda cur, prev, exp: cur == prev - exp,
    NextScanType.CHANGED_VALUE: lambda cur, prev, exp: cur != prev,
    NextScanType.UNCHANGED_VALUE: lambda cur, prev, exp: cur == prev,
}

# Refresh the UI at most every N matches during a scan.
UI_REFRESH_STEP = 750


@dataclass
class ScanRequest:
    """User-facing description of a scan, packaged for a worker."""

    spec: ValueTypeSpec
    length: int
    scan_type: ScanType  # ScanTypesEnum, or app-only NextScanType for refines
    value: Any  # parsed primary value, or (a, b) for ranges
    writeable_only: bool = False
    # Optional cached snapshot of memory regions, reused across scans to skip
    # the region enumeration step. Pass None to let the backend enumerate.
    memory_regions: Optional[Sequence[Dict]] = None


class _BaseWorker(QThread):
    progress = Signal(float)  # 0.0 … 100.0
    status = Signal(str)  # human status line
    error = Signal(str)
    chunk_ready = Signal(list)  # list[tuple[int, Any]]
    finished_ok = Signal(int)  # final match count

    def __init__(self, process: AbstractProcess, parent=None):
        super().__init__(parent)
        self._process = process
        self._cancelled = False

    def cancel(self) -> None:
        self._cancelled = True


class FirstScanWorker(_BaseWorker):
    """Performs the very first scan, finding every address that matches."""

    def __init__(self, process: AbstractProcess, request: ScanRequest, parent=None):
        super().__init__(process, parent)
        self._request = request

    def run(self) -> None:
        req = self._request
        try:
            # AOB pattern path: req.value is the IDA-style pattern string,
            # routed through search_by_pattern. writeable_only doesn't apply
            # (pattern scan filters by readability internally; restricting to
            # writable-only would silently miss code-section signatures, which
            # is the most common AOB use case).
            if req.spec.is_pattern:
                generator = self._process.search_by_pattern(
                    req.value,
                    progress_information=True,
                    memory_regions=req.memory_regions,
                )
            elif req.scan_type in (
                ScanTypesEnum.VALUE_BETWEEN,
                ScanTypesEnum.NOT_VALUE_BETWEEN,
            ):
                start, end = req.value
                generator = self._process.search_by_value_between(
                    req.spec.pytype,
                    req.length,
                    start,
                    end,
                    not_between=req.scan_type is ScanTypesEnum.NOT_VALUE_BETWEEN,
                    progress_information=True,
                    writeable_only=req.writeable_only,
                    memory_regions=req.memory_regions,
                )
            else:
                generator = self._process.search_by_value(
                    req.spec.pytype,
                    req.length,
                    req.value,
                    req.scan_type,
                    progress_information=True,
                    writeable_only=req.writeable_only,
                    memory_regions=req.memory_regions,
                )

            chunk: List = []
            count = 0
            # progress_information=True makes the generator yield (address, info)
            # tuples; the declared Union[int, Tuple[int, dict]] return type is
            # for the no-progress case. Cast so tuple-unpacking is well-typed.
            for address, info in cast(
                "Iterable[Tuple[int, Dict[str, Any]]]", generator
            ):
                if self._cancelled:
                    self.status.emit("Scan cancelled.")
                    break

                # The value field is filled in later via search_by_addresses;
                # the scan generator doesn't materialise the current value.
                chunk.append((address, None))
                count += 1

                if len(chunk) >= UI_REFRESH_STEP:
                    self.chunk_ready.emit(chunk)
                    chunk = []
                    progress = float(info.get("progress", 0.0)) * 100.0
                    self.progress.emit(progress)
                    self.status.emit(f"Found {count:,} addresses…")

            if chunk:
                self.chunk_ready.emit(chunk)

            self.progress.emit(100.0)
            self.finished_ok.emit(count)
        except Exception as exc:  # noqa: BLE001 — surface every backend error to the UI
            _LOG.warning("First scan failed: %s: %s", type(exc).__name__, exc)
            self.error.emit(f"{type(exc).__name__}: {exc}")


class RefineScanWorker(_BaseWorker):
    """
    Performs the "Next Scan" — i.e. re-reads every already-found address with
    ``search_by_addresses`` and keeps only those whose current value still
    satisfies the user's filter.

    Set ``filter_only=False`` to just refresh the values without dropping any
    addresses (this is what the "Update Values" button does).
    """

    def __init__(
        self,
        process: AbstractProcess,
        request: ScanRequest,
        addresses: Sequence[int],
        *,
        filter_only: bool = True,
        previous_values: Optional[Mapping[int, Any]] = None,
        parent=None,
    ):
        super().__init__(process, parent)
        self._request = request
        self._addresses = list(addresses)
        self._filter_only = filter_only
        # Snapshot of {address: value} from the previous scan, needed by the
        # Increased/Decreased/Changed/Unchanged comparisons.
        self._previous_values: Mapping[int, Any] = previous_values or {}

    def run(self) -> None:
        req = self._request
        compare = COMPARATORS.get(req.scan_type)
        prev_compare = PREVIOUS_COMPARATORS.get(req.scan_type)

        try:
            generator = self._process.search_by_addresses(
                req.spec.pytype,
                req.length,
                self._addresses,
                memory_regions=req.memory_regions,
            )

            chunk: List = []
            total = len(self._addresses)
            seen = 0
            kept = 0

            for address, current in generator:
                if self._cancelled:
                    self.status.emit("Scan cancelled.")
                    break

                seen += 1
                # Drop dead addresses outright. For a refine pass we also drop
                # addresses whose value no longer matches the filter. Either
                # way the address is appended to the chunk, so the receiver
                # observes a single batched update instead of one signal per
                # unreadable page (which on macOS can be most of the heap).
                if current is None:
                    chunk.append((address, None, False))
                    continue

                keeps = True
                if self._filter_only and prev_compare is not None:
                    # Increased/Decreased/Changed/Unchanged: compare against the
                    # value recorded at this address by the previous scan. With
                    # no baseline (address discovered without a value), keep it
                    # rather than guessing.
                    previous = self._previous_values.get(address)
                    try:
                        keeps = previous is not None and bool(
                            prev_compare(current, previous, req.value)
                        )
                    except TypeError as exc:
                        _LOG.debug(
                            "refine comparator raised TypeError at 0x%X "
                            "(scan_type=%s, current=%r, previous=%r, target=%r): %s",
                            address,
                            req.scan_type,
                            current,
                            previous,
                            req.value,
                            exc,
                        )
                        keeps = False
                elif self._filter_only and compare is not None:
                    try:
                        keeps = bool(compare(current, req.value))
                    except TypeError as exc:
                        # The comparator received incompatible types — usually
                        # a spec/value mismatch in the user's scan request.
                        # Surfacing this to the log lets us spot a real bug
                        # without aborting the whole refine pass.
                        _LOG.debug(
                            "refine comparator raised TypeError at 0x%X "
                            "(scan_type=%s, current=%r, target=%r): %s",
                            address,
                            req.scan_type,
                            current,
                            req.value,
                            exc,
                        )
                        keeps = False

                chunk.append((address, current, keeps))
                if keeps:
                    kept += 1

                if len(chunk) >= UI_REFRESH_STEP:
                    self.chunk_ready.emit(chunk)
                    chunk = []
                    if total:
                        self.progress.emit((seen / total) * 100.0)
                    self.status.emit(f"Checked {seen:,}/{total:,}, kept {kept:,}…")

            if chunk:
                self.chunk_ready.emit(chunk)

            self.progress.emit(100.0)
            self.finished_ok.emit(kept)
        except Exception as exc:  # noqa: BLE001 — surface every backend error to the UI
            _LOG.warning("Refine scan failed: %s: %s", type(exc).__name__, exc)
            self.error.emit(f"{type(exc).__name__}: {exc}")
