# -*- coding: utf-8 -*-

"""
Keep a backend generator bound to the open state of the process object that
created it.

Every listing and scan method returns a generator that captured the raw
handle (Windows), task port (macOS) or pid (Linux) when it was created, so
the open check must run on every resume, not only at creation: a generator
kept past ``close()`` would otherwise go on using a released handle — and
Windows hands a freed handle value to the next ``OpenProcess`` call, so after
``p1.close()`` and opening ``p2`` the next ``next(generator)`` could silently
read ``p2``.
"""

from typing import Callable, Generator, TypeVar


T = TypeVar("T")


def guard_generator(
    generator: Generator[T, None, None], require_open: Callable[[], None]
) -> Generator[T, None, None]:
    """
    Yield from ``generator``, calling ``require_open`` before every resume.

    ``require_open`` raises (``ClosedProcess``) once the process object is
    closed; the generator is then closed too, so its own cleanup (snapshot
    handles, ...) runs. The check is one attribute test per item: a backend
    generator can only be resumed while it is suspended at a ``yield``, which
    is exactly where ``close()`` can have run in between.
    """
    try:
        while True:
            require_open()
            try:
                item = next(generator)
            except StopIteration:
                return
            yield item
    finally:
        generator.close()
