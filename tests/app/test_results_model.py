# -*- coding: utf-8 -*-

"""
Tests for ``ResultsModel`` — the streaming model behind the "Found Addresses"
table — and the row-level helpers of ``ResultsView``.

The model is exercised without a view: ``patch_values`` is what the refine
worker feeds (via a blocking queued connection), and a refine that drops most
of a million rows must stay linear in the number of rows and announce
removals per contiguous run, not per row.

Needs a ``QApplication`` for the signal machinery but no ``qtbot``.
Skipped when ``PySide6`` isn't installed (the runtime dependency is opt-in via
the ``app`` extra).
"""

import os
import random

import pytest


pytest.importorskip("PySide6", reason="App tests require PySide6 (install with [app] extra).")

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


@pytest.fixture(scope="module")
def qapp():
    from PySide6.QtWidgets import QApplication

    return QApplication.instance() or QApplication([])


def test_contiguous_runs_collapses_adjacent_rows():
    from PyMemoryEditor.app.results_view import _contiguous_runs

    assert _contiguous_runs([]) == []
    assert _contiguous_runs([5]) == [(5, 5)]
    assert _contiguous_runs([1, 2, 3, 7, 9, 10]) == [(1, 3), (7, 7), (9, 10)]


def _filled_model(count):
    from PyMemoryEditor.app.results_view import ResultsModel

    model = ResultsModel()
    model.append_chunk([(0x1000 + 4 * i, i) for i in range(count)])
    return model


def test_patch_values_drops_scattered_rows_with_one_reset(qapp):
    """
    Drop three quarters of a 20k-row model at random. The survivors keep
    their order and values, the address→row index matches the lists, and —
    because the dropped rows form thousands of runs — the model is rebuilt
    once behind a single reset rather than announcing each run (the previous
    per-row ``list.pop`` + signal pair was quadratic).
    """
    count = 20_000
    model = _filled_model(count)
    removed = []
    resets = []
    model.rowsRemoved.connect(lambda _parent, first, last: removed.append((first, last)))
    model.modelReset.connect(lambda: resets.append(1))

    rng = random.Random(7)
    keep = set(rng.sample(range(count), count // 4))
    model.patch_values([(0x1000 + 4 * i, i + 100, i in keep) for i in range(count)])

    survivors = sorted(keep)
    assert model.count() == len(survivors)
    assert model.all_addresses() == [0x1000 + 4 * i for i in survivors]
    assert [model.value_at(r) for r in range(model.count())] == [i + 100 for i in survivors]
    # Previous column carries the value from before the patch.
    assert model._previous[: 3] == [survivors[0], survivors[1], survivors[2]]
    # Index agrees with the lists for every surviving address.
    assert all(model._row_of(a) == r for r, a in enumerate(model._addresses))
    assert len(model._index) == model.count()

    assert resets == [1]
    assert removed == []


def test_patch_values_announces_one_removal_per_contiguous_run(qapp):
    """A refine dropping a few blocks of neighbours signals per block."""
    model = _filled_model(1_000)
    removed = []
    resets = []
    model.rowsRemoved.connect(lambda _parent, first, last: removed.append((first, last)))
    model.modelReset.connect(lambda: resets.append(1))

    drop = set(range(10, 20)) | set(range(500, 503)) | {999}
    model.patch_values([(0x1000 + 4 * i, i, i not in drop) for i in range(1_000)])

    assert resets == []
    # Highest run first, so earlier row numbers stay valid as the view applies them.
    assert removed == [(999, 999), (500, 502), (10, 19)]
    assert model.count() == 1_000 - len(drop)
    assert model.address_at(10) == 0x1000 + 4 * 20
    assert all(model._row_of(a) == r for r, a in enumerate(model._addresses))


def test_a_chunked_refine_keeps_rows_right_without_rebuilding_the_index(qapp):
    """
    A refine arrives as many small chunks. Every chunk used to rebuild the
    whole address→row dict after dropping its rows, which made a refine
    quadratic in the result count. The index is now adjusted incrementally:
    whatever order the chunks arrive in, and whether they drop a scattered
    set (reset path) or a few blocks (per-run path), every surviving address
    still maps to its row and patches land on the right one.
    """
    from PyMemoryEditor.app import results_view

    count = 6_000
    model = _filled_model(count)
    rng = random.Random(11)
    order = list(range(count))
    rng.shuffle(order[count // 2:])  # first half in order, second shuffled
    keep = {i for i in range(count) if rng.random() < 0.4 or i % 97 == 0}

    rebuilds = []
    original = results_view.ResultsModel._reindex
    model._reindex = lambda: (rebuilds.append(1), original(model))

    for start in range(0, count, 750):
        model.patch_values(
            [(0x1000 + 4 * i, i + 1, i in keep) for i in order[start:start + 750]]
        )
        assert all(model._row_of(a) == r for r, a in enumerate(model._addresses))

    survivors = sorted(keep)
    assert model.all_addresses() == [0x1000 + 4 * i for i in survivors]
    assert [model.value_at(r) for r in range(model.count())] == [i + 1 for i in survivors]
    # Amortised: rebuilt only when the dropped rows outnumber the kept ones,
    # never once per chunk.
    assert len(rebuilds) <= 2

    # A second pass on the shrunken model still lands every value correctly.
    model.patch_values([(0x1000 + 4 * i, -i, True) for i in survivors])
    assert [model.value_at(r) for r in range(model.count())] == [-i for i in survivors]


def test_duplicate_addresses_fall_back_to_a_rebuilt_index(qapp):
    model = _filled_model(4)
    model.append_chunk([(0x1000, 9)])  # 0x1000 now appears twice
    model.patch_values([(0x1004, 0, False)])
    assert model.all_addresses() == [0x1000, 0x1008, 0x100C, 0x1000]
    assert all(
        model._row_of(a) == r
        for r, a in enumerate(model._addresses)
        if a != 0x1000
    )


def test_patch_values_coalesces_data_changed_per_run(qapp):
    model = _filled_model(10)
    changed = []
    model.dataChanged.connect(
        lambda top_left, bottom_right, _roles=None: changed.append(
            (top_left.row(), bottom_right.row())
        )
    )
    # Rows 0-2 and 5-6 patched, rows 3, 4 and 7-9 untouched (absent), nothing dropped.
    model.patch_values([(0x1000 + 4 * i, 50 + i, True) for i in (0, 1, 2, 5, 6)])

    assert changed == [(0, 2), (5, 6)]
    assert model.value_at(6) == 56 and model._previous[6] == 6
    assert model.value_at(3) == 3 and model._previous[3] is None


def test_dropping_every_row_and_dropping_none_are_both_fine(qapp):
    model = _filled_model(50)
    model.patch_values([(0x1000 + 4 * i, 0, True) for i in range(50)])
    assert model.count() == 50

    model.patch_values([(0x1000 + 4 * i, 0, False) for i in range(50)])
    assert model.count() == 0
    assert model._index == {}
    assert model.rowCount() == 0

    # Unknown addresses are ignored, never raise.
    model.patch_values([(0xDEAD, 1, False)])
    assert model.count() == 0


def test_rows_dropped_then_appended_keep_a_consistent_index(qapp):
    model = _filled_model(6)
    model.patch_values([(0x1000 + 4 * i, 0, i % 2 == 0) for i in range(6)])
    model.append_chunk([(0x9000, 1), (0x9004, 2)])

    assert model.all_addresses() == [0x1000, 0x1008, 0x1010, 0x9000, 0x9004]
    assert model._row_of(0x9004) == 4
    assert model.address_at(4) == 0x9004


def test_context_menu_emit_skips_a_row_that_vanished(qapp):
    """
    The context-menu actions look the address up when they fire, not when
    the menu opened: a refine running during the menu's nested event loop can
    drop the row, and emitting ``None`` on a ``qulonglong`` signal is a
    TypeError inside a Qt slot.
    """
    from PyMemoryEditor.app.results_view import ResultsView

    view = ResultsView()
    model = _filled_model(3)
    view.setModel(model)
    got = []
    view.open_in_hex_viewer.connect(lambda address: got.append(address))

    view._emit_for_row(view.open_in_hex_viewer, 2)
    assert got == [0x1008]

    model.patch_values([(0x1008, 0, False)])  # the row is gone now
    view._emit_for_row(view.open_in_hex_viewer, 2)
    assert got == [0x1008]  # nothing emitted, nothing raised
