# -*- coding: utf-8 -*-

"""
macOS-only test: which ``kern_return_t`` values a scan loop is allowed to walk
past.

The scan loops (``iter_search_results`` / ``iter_pattern_results``) skip a chunk
they classify as transient and re-raise anything else, so this classification is
the line between "a scan of a live process completes" and "it aborts on the
first page the kernel declines to hand over". ``KERN_MEMORY_ERROR`` sat on the
wrong side of it: file-backed read-only mappings (code segments, dylibs, the
dyld shared cache) return it routinely, so every pattern scan — and any value
scan with ``writeable_only`` off — died partway through.
"""

import sys

import pytest


if sys.platform != "darwin":
    pytest.skip("macOS-only module", allow_module_level=True)


from PyMemoryEditor.macos.functions import (  # noqa: E402
    MachPartialReadError,
    MachReadError,
    _is_transient,
)
from PyMemoryEditor.macos.types import (  # noqa: E402
    KERN_FAILURE,
    KERN_INVALID_ADDRESS,
    KERN_INVALID_ARGUMENT,
    KERN_MEMORY_ERROR,
    KERN_MEMORY_FAILURE,
    KERN_NO_ACCESS,
    KERN_PROTECTION_FAILURE,
)


# mach/kern_return.h documents each of these as a page the scan may walk past.
# KERN_MEMORY_ERROR's own comment is explicit: "This failure may be temporary;
# future attempts to access this same data may succeed."
@pytest.mark.parametrize(
    "kr",
    (
        KERN_INVALID_ADDRESS,
        KERN_INVALID_ARGUMENT,
        KERN_NO_ACCESS,
        KERN_MEMORY_ERROR,
    ),
)
def test_a_vanished_page_lets_the_scan_continue(kr):
    assert _is_transient(MachReadError(kr, "read failed (kr=%d)" % kr))


# The complement matters just as much: a permission or configuration problem
# must reach the caller instead of being silently scanned past. The header puts
# KERN_MEMORY_FAILURE directly above KERN_MEMORY_ERROR and documents it as
# permanent, which is exactly the distinction being drawn here; KERN_FAILURE is
# what task_for_pid returns without the debugger entitlement.
@pytest.mark.parametrize(
    "kr", (KERN_FAILURE, KERN_PROTECTION_FAILURE, KERN_MEMORY_FAILURE)
)
def test_a_real_failure_still_propagates(kr):
    assert not _is_transient(MachReadError(kr, "read failed (kr=%d)" % kr))


def test_a_short_read_lets_the_scan_continue():
    """
    A partial read means the transfer straddled a page that went away, so the
    chunk is skipped like any other vanished page — the class carries
    KERN_INVALID_ADDRESS for exactly that reason. Pinned here because the
    behaviour rides on that constructor choice rather than on anything local.
    """
    assert _is_transient(MachPartialReadError(0x1000, 8, 64))


def test_a_non_mach_error_is_never_transient():
    assert not _is_transient(OSError("some unrelated failure"))
    assert not _is_transient(ValueError("not an OSError at all"))
