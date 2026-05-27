# -*- coding: utf-8 -*-

"""
Live handle to a value living in another process's address space.

A :class:`RemotePointer` bundles together the three things you otherwise have
to carry by hand on every access — the process, *where* the value lives, and
*how* to interpret the bytes there — behind a single ``.value`` property::

    hp = RemotePointer(process, 0x14010F4F4, [0x0, 0x158], pytype=int, bufflength=4)
    print(hp.value)   # read
    hp.value = 9999   # write

The win over a bare ``read_process_memory`` call is that a pointer **re-resolves
its address on every access**. When ``offsets`` is given, each ``.value`` read
walks the chain again with :meth:`AbstractProcess.resolve_pointer_chain`, so the
handle keeps working even as the target moves its objects around the heap — the
same reason a Cheat Engine pointer entry survives a level reload.

Because it is built purely on the abstract ``read_process_memory`` /
``write_process_memory`` / ``resolve_pointer_chain`` API, it behaves identically
on Windows, Linux and macOS.
"""

from typing import Optional, Sequence, Tuple, Type, TypeVar, TYPE_CHECKING, Union

if TYPE_CHECKING:
    from .abstract import AbstractProcess


T = TypeVar("T")


class RemotePointer:
    """A re-resolving, read/write handle to a typed value in a target process.

    :param process: the open process the value lives in (any ``OpenProcess``
        backend).
    :param base_address: starting address. For a direct handle this is the
        address of the value itself; for a pointer chain it is typically
        ``module_base + static_offset``.
    :param offsets: how to reach the value from ``base_address``:

        * ``None`` (default) — **direct handle**: ``address`` *is*
          ``base_address``, with no dereferencing. Use this to wrap an address
          you already found (e.g. from :meth:`AbstractProcess.search_by_value`).
        * a sequence (including the empty list ``[]``) — the value sits at the
          end of a pointer chain. ``address`` is recomputed on every access via
          :meth:`AbstractProcess.resolve_pointer_chain`, so the same chain
          semantics apply: ``[]`` dereferences ``base_address`` once; a
          non-empty list walks each offset, dereferencing all but the last.

    :param pytype: how to interpret the bytes at the resolved address (bool,
        int, float, str or bytes). Defaults to ``int``.
    :param bufflength: value size in bytes. May be ``None`` for numeric types
        (defaults: int→4, float→8, bool→1); ``str`` and ``bytes`` require an
        explicit size.
    :param ptr_size: pointer width used when walking ``offsets`` — 8 for 64-bit
        targets (default), 4 for 32-bit. Ignored for a direct handle.

    Example
    -------
    Cheat-table entry ``"game.exe"+0x10F4F4 -> [+0x0] -> [+0x158]`` (HP)::

        module = next(m for m in process.get_modules() if m.name == "game.exe")
        hp = RemotePointer(
            process, module.base_address + 0x10F4F4, [0x0, 0x158],
            pytype=int, bufflength=4,
        )
        hp.value -= 10        # take 10 damage, wherever the object moved to
    """

    def __init__(
        self,
        process: "AbstractProcess",
        base_address: int,
        offsets: Optional[Sequence[int]] = None,
        *,
        pytype: Type = int,
        bufflength: Optional[int] = None,
        ptr_size: int = 8,
    ):
        self._process = process
        self._base_address = base_address
        # Materialize the sequence so later mutation of a caller-held list can't
        # silently change where this pointer resolves. ``None`` is preserved as
        # the "direct handle" sentinel and kept distinct from an empty chain.
        self._offsets = None if offsets is None else tuple(offsets)
        self._pytype = pytype
        self._bufflength = bufflength
        self._ptr_size = ptr_size

    @property
    def process(self) -> "AbstractProcess":
        """The process this pointer reads from / writes to."""
        return self._process

    @property
    def base_address(self) -> int:
        """The starting address the pointer was built with."""
        return self._base_address

    @property
    def offsets(self) -> Optional[Sequence[int]]:
        """The pointer-chain offsets, or ``None`` for a direct handle."""
        return self._offsets

    @property
    def address(self) -> int:
        """
        The address the value currently lives at.

        For a direct handle this is ``base_address`` unchanged. For a pointer
        chain it is recomputed on every read of this property by walking the
        chain — so each access reflects where the target's pointers point *now*.
        """
        if self._offsets is None:
            return self._base_address
        return self._process.resolve_pointer_chain(
            self._base_address, self._offsets, ptr_size=self._ptr_size
        )

    @property
    def value(self):
        """Read and return the value at :attr:`address` using the bound type."""
        return self._process.read_process_memory(
            self.address, self._pytype, self._bufflength
        )

    @value.setter
    def value(self, new_value: Union[bool, int, float, str, bytes]) -> None:
        """Write ``new_value`` to :attr:`address` using the bound type."""
        self._process.write_process_memory(
            self.address, self._pytype, self._bufflength, new_value
        )

    def read(
        self,
        pytype: Optional[Type[T]] = None,
        bufflength: Optional[int] = None,
    ) -> T:
        """
        Read the value at :attr:`address`, optionally overriding the bound type.

        Lets a single pointer be reinterpreted ad hoc (e.g. peek the same
        address as ``bytes``) without building a second handle. Falls back to
        the type and size the pointer was constructed with.
        """
        return self._process.read_process_memory(
            self.address,
            self._pytype if pytype is None else pytype,
            self._bufflength if bufflength is None else bufflength,
        )

    def write(
        self,
        value: Union[bool, int, float, str, bytes],
        pytype: Optional[Type] = None,
        bufflength: Optional[int] = None,
    ) -> Union[bool, int, float, str, bytes]:
        """
        Write ``value`` to :attr:`address`, optionally overriding the bound type.

        Mirrors :meth:`read`; returns whatever ``write_process_memory`` returns.
        """
        return self._process.write_process_memory(
            self.address,
            self._pytype if pytype is None else pytype,
            self._bufflength if bufflength is None else bufflength,
            value,
        )

    def _shift(self, delta: int) -> "RemotePointer":
        """
        Return a new pointer whose resolved address is this one's ``+ delta``,
        carrying over ``pytype`` / ``bufflength`` / ``ptr_size`` unchanged.

        The shift is folded into the address arithmetic *lazily*: for a pointer
        chain it is added to the final offset, so the returned pointer still
        re-walks the chain on every access — ``(hp + 4)`` keeps following the
        target as it moves, it doesn't snapshot the address at shift time.
        """
        new_offsets: Optional[Tuple[int, ...]]
        if self._offsets is None:
            # Direct handle: just move the base address.
            new_base, new_offsets = self._base_address + delta, None
        elif len(self._offsets) == 0:
            # offsets=[] dereferences base once; +delta means deref then +delta,
            # which is exactly the chain [delta].
            new_base, new_offsets = self._base_address, (delta,)
        else:
            # Adding to the final address == adding to the last (non-deref) hop.
            new_base = self._base_address
            new_offsets = self._offsets[:-1] + (self._offsets[-1] + delta,)

        return RemotePointer(
            self._process,
            new_base,
            new_offsets,
            pytype=self._pytype,
            bufflength=self._bufflength,
            ptr_size=self._ptr_size,
        )

    def __add__(self, delta: int) -> "RemotePointer":
        """C-style pointer arithmetic: a new pointer ``delta`` bytes ahead.

        Does **not** touch memory — to change the stored value use ``.value``
        (e.g. ``ptr.value += 10``).
        """
        if not isinstance(delta, int):
            return NotImplemented
        return self._shift(delta)

    __radd__ = __add__  # support ``offset + ptr`` as well as ``ptr + offset``

    def __sub__(self, other: Union[int, "RemotePointer"]) -> Union[int, "RemotePointer"]:
        """``ptr - n`` → a pointer ``n`` bytes behind; ``ptr - other`` → the
        byte distance between the two resolved addresses (like C pointers).
        """
        if isinstance(other, RemotePointer):
            return self.address - other.address
        if not isinstance(other, int):
            return NotImplemented
        return self._shift(-other)

    def __int__(self) -> int:
        """The resolved :attr:`address` — handy for arithmetic and logging."""
        return self.address

    def __repr__(self) -> str:
        chain = "" if self._offsets is None else " -> %r" % (list(self._offsets),)
        return "<RemotePointer base=0x%X%s pytype=%s>" % (
            self._base_address,
            chain,
            getattr(self._pytype, "__name__", self._pytype),
        )


__all__ = ("RemotePointer",)
