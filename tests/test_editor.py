# -*- coding: utf-8 -*-

"""
End-to-end read/write/search tests against the current process.

All tests share a single ``OpenProcess`` handle via a module-scoped fixture so
they don't depend on declaration order (`pytest-randomly` and parallel runners
are safe) and don't pollute stdout at import time. Heuristic thresholds
(found/total ratios) are tolerated because some target addresses live in
regions outside our control and may have their values changed mid-scan.
"""

import ctypes
import os
import random
import sys
from typing import Iterator

import pytest

from PyMemoryEditor import OpenProcess, ScanTypesEnum


# The default permission on Windows already includes read+write, but spell
# the mask out here so the suite stays explicit about what it needs. Linux
# and macOS ignore the `permission` kwarg.
if sys.platform == "win32":
    from PyMemoryEditor import ProcessOperationsEnum

    _PERMISSION = (
        ProcessOperationsEnum.PROCESS_VM_READ.value
        | ProcessOperationsEnum.PROCESS_VM_WRITE.value
        | ProcessOperationsEnum.PROCESS_VM_OPERATION.value
        # PROCESS_QUERY_INFORMATION is required by VirtualQueryEx, which the
        # search_by_value* / search_by_addresses code paths use to enumerate
        # the target's memory regions. Without it the scan returns nothing.
        | ProcessOperationsEnum.PROCESS_QUERY_INFORMATION.value
    )
else:
    _PERMISSION = None


def _generate_text(size: int) -> str:
    return "".join(chr(random.randint(ord("A"), ord("Z"))) for _ in range(size))


@pytest.fixture(scope="module")
def process() -> Iterator[OpenProcess]:
    """Open `OpenProcess` against the current process for the whole module."""
    if _PERMISSION is not None:
        handle = OpenProcess(pid=os.getpid(), permission=_PERMISSION)
    else:
        handle = OpenProcess(pid=os.getpid())
    try:
        yield handle
    finally:
        handle.close()


def test_read_bool(process):
    target_value_1 = ctypes.c_bool(True)
    target_value_2 = ctypes.c_bool(False)

    address_1 = ctypes.addressof(target_value_1)
    address_2 = ctypes.addressof(target_value_2)

    data_length = ctypes.sizeof(target_value_1)

    result_1 = process.read_process_memory(address_1, bool, data_length)
    result_2 = process.read_process_memory(address_2, bool, data_length)

    assert type(result_1) is bool and result_1 == target_value_1.value
    assert type(result_2) is bool and result_2 == target_value_2.value


def test_read_float(process):
    target_value = ctypes.c_double(random.random())
    address = ctypes.addressof(target_value)
    data_length = ctypes.sizeof(target_value)

    result = process.read_process_memory(address, float, data_length)
    assert type(result) is float and result == target_value.value


def test_read_int(process):
    target_value = ctypes.c_int(random.randint(0, 10000))
    address = ctypes.addressof(target_value)
    data_length = ctypes.sizeof(target_value)

    result = process.read_process_memory(address, int, data_length)
    assert type(result) is int and result == target_value.value


def test_read_string(process):
    target_value = ctypes.create_string_buffer(20)
    target_value.value = _generate_text(20).encode()

    address = ctypes.addressof(target_value)
    data_length = ctypes.sizeof(target_value)

    result = process.read_process_memory(address, str, data_length)
    assert type(result) is str and result == target_value.value.decode()


def test_write_bool(process):
    original_value_1 = True
    original_value_2 = False

    new_value_1 = not original_value_1
    new_value_2 = not original_value_2

    target_value_1 = ctypes.c_bool(original_value_1)
    target_value_2 = ctypes.c_bool(original_value_2)

    address_1 = ctypes.addressof(target_value_1)
    address_2 = ctypes.addressof(target_value_2)

    data_length = ctypes.sizeof(target_value_1)

    process.write_process_memory(address_1, bool, data_length, new_value_1)
    process.write_process_memory(address_2, bool, data_length, new_value_2)

    assert (
        target_value_1.value != original_value_1 and target_value_1.value == new_value_1
    )
    assert (
        target_value_2.value != original_value_2 and target_value_2.value == new_value_2
    )


def test_write_float(process):
    original_value = random.random()
    new_value = original_value + 7651

    target_value = ctypes.c_double(original_value)
    address = ctypes.addressof(target_value)
    data_length = ctypes.sizeof(target_value)

    process.write_process_memory(address, float, data_length, new_value)
    assert target_value.value != original_value and target_value.value == new_value


def test_write_int(process):
    original_value = random.randint(0, 10000)
    new_value = original_value + 7651

    target_value = ctypes.c_int(original_value)
    address = ctypes.addressof(target_value)
    data_length = ctypes.sizeof(target_value)

    process.write_process_memory(address, int, data_length, new_value)
    assert target_value.value != original_value and target_value.value == new_value


def test_write_string(process):
    original_value = _generate_text(20).encode()
    new_value = _generate_text(20).encode()

    target_value = ctypes.create_string_buffer(20)
    target_value.value = original_value

    address = ctypes.addressof(target_value)
    data_length = ctypes.sizeof(target_value)

    process.write_process_memory(address, str, data_length, new_value.decode())
    assert target_value.value != original_value and target_value.value == new_value


def test_search_by_int_addresses(process):
    test_length = 10

    target_values = [ctypes.c_int(random.randint(0, 10000)) for _ in range(test_length)]
    data_length = ctypes.sizeof(target_values[0])

    targets_by_address = {ctypes.addressof(v): v for v in target_values}
    addresses = list(targets_by_address.keys())

    for address, value in process.search_by_addresses(int, data_length, addresses):
        assert targets_by_address[address].value == value and type(value) is int


def test_search_by_float_addresses(process):
    test_length = 10

    target_values = [
        ctypes.c_double(random.randint(0, 10000) / random.randint(1, 10000))
        for _ in range(test_length)
    ]
    data_length = ctypes.sizeof(target_values[0])

    targets_by_address = {ctypes.addressof(v): v for v in target_values}
    addresses = list(targets_by_address.keys())

    for address, value in process.search_by_addresses(float, data_length, addresses):
        assert targets_by_address[address].value == value and type(value) is float


def test_search_by_string_addresses(process):
    string_length, test_length = 20, 10

    target_values = []
    for _ in range(test_length):
        value = ctypes.create_string_buffer(string_length)
        value.value = _generate_text(string_length).encode()
        target_values.append(value)

    data_length = ctypes.sizeof(target_values[0])

    targets_by_address = {ctypes.addressof(v): v for v in target_values}
    addresses = list(targets_by_address.keys())

    for address, value in process.search_by_addresses(str, data_length, addresses):
        assert (
            targets_by_address[address].value.decode() == value and type(value) is str
        )


def test_search_by_int(process):
    test_length = 10

    target_values = [ctypes.c_int(random.randint(0, 10000)) for _ in range(test_length)]
    addresses = [ctypes.addressof(v) for v in target_values]
    data_length = ctypes.sizeof(target_values[0])

    min_value = min(v.value for v in target_values)
    max_value = max(v.value for v in target_values)

    total = 0
    found = 0
    correct = 0

    for found_address in process.search_by_value_between(
        int, data_length, min_value, max_value
    ):
        if found_address in addresses:
            addresses.remove(found_address)
            found += 1

        total += 1

        # A page may have been decommitted between scan and read (genuine race
        # condition); the syscall now surfaces it as OSError instead of
        # returning zeros.
        try:
            value = process.read_process_memory(found_address, int, data_length)
            if min_value <= value <= max_value:
                correct += 1
        except OSError:
            pass

    assert found / test_length >= 0.7
    # Some addresses are beyond our control and may have their values changed.
    assert correct / total >= 0.7


def test_search_by_float(process):
    test_length = 10

    target_values = [
        ctypes.c_double(random.randint(0, 10000)) for _ in range(test_length)
    ]
    addresses = [ctypes.addressof(v) for v in target_values]
    data_length = ctypes.sizeof(target_values[0])

    min_value = min(v.value for v in target_values)
    max_value = max(v.value for v in target_values)

    total = 0
    found = 0
    correct = 0

    for found_address in process.search_by_value_between(
        float, data_length, min_value, max_value
    ):
        if found_address in addresses:
            addresses.remove(found_address)
            found += 1

        total += 1

        # Same race as test_search_by_int — tolerate OSError on read.
        try:
            value = process.read_process_memory(found_address, float, data_length)
            if min_value <= value <= max_value:
                correct += 1
        except OSError:
            pass

    assert found / test_length >= 0.7
    assert correct / total >= 0.7


def test_search_by_string(process):
    string_length, test_length = 20, 10

    target_values = []
    for _ in range(test_length):
        value = ctypes.create_string_buffer(string_length)
        value.value = _generate_text(string_length).encode()
        target_values.append(value)

    data_length = ctypes.sizeof(target_values[0])

    total = 0
    found = 0
    correct = 0

    for target_value in target_values:
        for found_address in process.search_by_value(
            str, data_length, target_value.value, ScanTypesEnum.EXACT_VALUE
        ):
            if found_address == ctypes.addressof(target_value):
                found += 1

            total += 1

            try:
                value = process.read_process_memory(found_address, str, data_length)
                if value == target_value.value.decode():
                    correct += 1
            except (OSError, ValueError, UnicodeDecodeError):
                # The address may belong to another region by the time we read
                # it back, or hold non-decodable bytes. Either way, skip it.
                pass

    assert found / test_length >= 0.7
    assert correct / total >= 0.7


def test_search_by_string_between(process):
    string_length, test_length = 20, 10

    values = []
    for _ in range(test_length * 2):
        value = ctypes.create_string_buffer(string_length)
        value.value = _generate_text(string_length).encode()
        values.append(value)

    values.sort(key=lambda target_value: target_value.value)

    # Half of the set are targets; the other half are noise that the scanner
    # must NOT return.
    target_values = values[test_length // 4 : test_length - test_length // 4]

    noise_addresses = {ctypes.addressof(v) for v in values}
    target_addresses = {ctypes.addressof(v) for v in target_values}

    data_length = ctypes.sizeof(target_values[0])

    min_value = target_values[0].value
    max_value = target_values[-1].value

    found = 0

    for found_address in process.search_by_value_between(
        str, data_length, min_value, max_value
    ):
        if found_address in target_addresses:
            found += 1
        elif found_address in noise_addresses:
            raise ValueError(
                "Scanner returned the address of a clearly invalid string."
            )

    assert found / test_length >= 0.5
