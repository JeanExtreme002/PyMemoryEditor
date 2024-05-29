from PyMemoryEditor import OpenProcess, ScanTypesEnum, __version__
from os import getpid
from typing import Optional
import ctypes
import platform
import random

print("Testing PyMemoryEditor version %s." % __version__)

print("\nOS Information: {} - {} {}".format(platform.platform(), *platform.architecture()[::-1]))
print("Processor Information: {} | {}\n".format(platform.machine(), platform.processor()))

process_id = getpid()
process: Optional[OpenProcess] = None


def generate_text(size):
    # Return a random text.
    return "".join([chr(random.randint(ord("A"), ord("Z"))) for letter in range(size)])


def test_open_process():
    global process

    # Open the process to write and read the process memory.
    process = OpenProcess(pid=process_id)


def test_read_bool():
    # Compare with True and False values.
    target_value_1 = ctypes.c_bool(True)
    target_value_2 = ctypes.c_bool(False)

    address_1 = ctypes.addressof(target_value_1)
    address_2 = ctypes.addressof(target_value_2)

    data_length = ctypes.sizeof(target_value_1)

    # Read the process memory and compare the results.
    result_1 = process.read_process_memory(address_1, bool, data_length)
    result_2 = process.read_process_memory(address_2, bool, data_length)

    assert type(result_1) is bool and result_1 == target_value_1.value
    assert type(result_2) is bool and result_2 == target_value_2.value


def test_read_float():
    # Get a random value to compare the result.
    target_value = ctypes.c_double(random.random())
    address = ctypes.addressof(target_value)
    data_length = ctypes.sizeof(target_value)

    # Read the process memory and compare the result.
    result = process.read_process_memory(address, float, data_length)
    assert type(result) is float and result == target_value.value


def test_read_int():
    # Get a random value to compare the result.
    target_value = ctypes.c_int(random.randint(0, 10000))
    address = ctypes.addressof(target_value)
    data_length = ctypes.sizeof(target_value)

    # Read the process memory and compare the result.
    result = process.read_process_memory(address, int, data_length)
    assert type(result) is int and result == target_value.value


def test_read_string():
    # Get a random text to compare the result.
    target_value = ctypes.create_string_buffer(20)
    target_value.value = generate_text(20).encode()

    address = ctypes.addressof(target_value)
    data_length = ctypes.sizeof(target_value)

    # Read the process memory and compare the result.
    result = process.read_process_memory(address, str, data_length)
    assert type(result) is str and result == target_value.value.decode()


def test_write_bool():
    # Compare with True and False values.
    original_value_1 = True
    original_value_2 = False

    new_value_1 = not original_value_1
    new_value_2 = not original_value_2

    target_value_1 = ctypes.c_bool(original_value_1)
    target_value_2 = ctypes.c_bool(original_value_2)

    address_1 = ctypes.addressof(target_value_1)
    address_2 = ctypes.addressof(target_value_2)

    data_length = ctypes.sizeof(target_value_1)

    # Write to the process memory and compare the results.
    process.write_process_memory(address_1, bool, data_length, new_value_1)
    process.write_process_memory(address_2, bool, data_length, new_value_2)

    assert target_value_1.value != original_value_1 and target_value_1.value == new_value_1
    assert target_value_2.value != original_value_2 and target_value_2.value == new_value_2


def test_write_float():
    # Get a random value to compare the result.
    original_value = random.random()
    new_value = original_value + 7651

    target_value = ctypes.c_double(original_value)
    address = ctypes.addressof(target_value)
    data_length = ctypes.sizeof(target_value)

    # Write to the process memory and compare the result.
    process.write_process_memory(address, float, data_length, new_value)
    assert target_value.value != original_value and target_value.value == new_value


def test_write_int():
    # Get a random value to compare the result.
    original_value = random.randint(0, 10000)
    new_value = original_value + 7651

    target_value = ctypes.c_int(original_value)
    address = ctypes.addressof(target_value)
    data_length = ctypes.sizeof(target_value)

    # Write to the process memory and compare the result.
    process.write_process_memory(address, int, data_length, new_value)
    assert target_value.value != original_value and target_value.value == new_value


def test_write_string():
    # Get a random text to compare the result.
    original_value = generate_text(20).encode()
    new_value = generate_text(20).encode()

    target_value = ctypes.create_string_buffer(20)
    target_value.value = original_value

    address = ctypes.addressof(target_value)
    data_length = ctypes.sizeof(target_value)

    # Write to the process memory and compare the result.
    process.write_process_memory(address, str, data_length, new_value.decode())
    assert target_value.value != original_value and target_value.value == new_value


def test_search_by_int_addresses():
    # Get random values to compare the result.
    test_length = 10

    target_values = [ctypes.c_int(random.randint(0, 10000)) for i in range(test_length)]
    data_length = ctypes.sizeof(target_values[0])

    target_values = {ctypes.addressof(v): v for v in target_values}
    addresses = list(target_values.keys())

    for address, value in process.search_by_addresses(int, data_length, addresses):
        assert target_values[address].value == value and type(value) is int


def test_search_by_float_addresses():
    # Get random values to compare the result.
    test_length = 10

    target_values = [ctypes.c_double(random.randint(0, 10000) / random.randint(0, 10000)) for i in range(test_length)]
    data_length = ctypes.sizeof(target_values[0])

    target_values = {ctypes.addressof(v): v for v in target_values}
    addresses = list(target_values.keys())

    for address, value in process.search_by_addresses(float, data_length, addresses):
        assert target_values[address].value == value and type(value) is float


def test_search_by_string_addresses():
    # Get random values to compare the result.
    string_length, test_length = 20, 10

    target_values = list()

    for i in range(test_length):
        value = ctypes.create_string_buffer(string_length)
        value.value = generate_text(string_length).encode()
        target_values.append(value)

    data_length = ctypes.sizeof(target_values[0])

    target_values = {ctypes.addressof(v): v for v in target_values}
    addresses = list(target_values.keys())

    for address, value in process.search_by_addresses(str, data_length, addresses):
        assert target_values[address].value.decode() == value and type(value) is str


def test_search_by_int():
    # Get random values to compare the result.
    test_length = 10

    target_values = [ctypes.c_int(random.randint(0, 10000)) for i in range(test_length)]
    addresses = [ctypes.addressof(v) for v in target_values]
    data_length = ctypes.sizeof(target_values[0])

    min_value = min([v.value for v in target_values])
    max_value = max([v.value for v in target_values])

    total = 0
    found = 0
    correct = 0

    # Get addresses of values exact or smaller than max_value.
    for found_address in process.search_by_value_between(int, data_length, min_value, max_value):

        # Check if the found address is a target address.
        if found_address in addresses:
            addresses.remove(found_address)
            found += 1

        total += 1

        # Check if the address really points to a valid value.
        value = process.read_process_memory(found_address, int, data_length)
        if min_value <= value <= max_value: correct += 1

    assert found / test_length >= 0.7
    assert correct / total >= 0.7  # Some of the addresses are beyond our control and may have their values changed.


def test_search_by_float():
    # Get random values to compare the result.
    test_length = 10

    target_values = [ctypes.c_double(random.randint(0, 10000)) for i in range(test_length)]
    addresses = [ctypes.addressof(v) for v in target_values]
    data_length = ctypes.sizeof(target_values[0])

    min_value = min([v.value for v in target_values])
    max_value = max([v.value for v in target_values])

    total = 0
    found = 0
    correct = 0

    # Get addresses of values exact or smaller than max_value.
    for found_address in process.search_by_value_between(float, data_length, min_value, max_value):

        # Check if the found address is a target address.
        if found_address in addresses:
            addresses.remove(found_address)
            found += 1

        total += 1

        # Check if the address really points to a valid value.
        value = process.read_process_memory(found_address, float, data_length)
        if min_value <= value <= max_value: correct += 1

    assert found / test_length >= 0.7
    assert correct / total >= 0.7  # Some of the addresses are beyond our control and may have their values changed.


def test_search_by_string():
    # Get random values to compare the result.
    string_length, test_length = 20, 10

    target_values = list()

    for i in range(test_length):
        value = ctypes.create_string_buffer(string_length)
        value.value = generate_text(string_length).encode()
        target_values.append(value)

    data_length = ctypes.sizeof(target_values[0])

    total = 0
    found = 0
    correct = 0

    # Get addresses of values exact or smaller than max_value.
    for target_value in target_values:
        for found_address in process.search_by_value(str, data_length, target_value.value, ScanTypesEnum.EXACT_VALUE):

            # Check if the found address is the target address.
            if found_address == ctypes.addressof(target_value):
                found += 1

            total += 1

            # Check if the address really points to a valid value.
            try:
                value = process.read_process_memory(found_address, str, data_length)
                if value == target_value.value.decode(): correct += 1
            except: pass

    assert found / test_length >= 0.7
    assert correct / total >= 0.7  # Some of the addresses are beyond our control and may have their values changed.


def test_search_by_string_between():
    # Get random values to compare the result.
    string_length, test_length = 20, 10

    values = list()

    for i in range(test_length * 2):
        value = ctypes.create_string_buffer(string_length)
        value.value = generate_text(string_length).encode()
        values.append(value)

    values.sort(key=lambda target_value: target_value.value)

    # Half of the set of strings is the target and the other half contains string that should be ignored by the scanner.
    target_values = [target_value for target_value in values[test_length // 4: test_length - test_length // 4]]

    addresses = [ctypes.addressof(v) for v in values]
    target_addresses = [ctypes.addressof(v) for v in target_values]

    data_length = ctypes.sizeof(target_values[0])

    min_value = target_values[0].value
    max_value = target_values[-1].value

    found = 0

    # Get addresses of values exact or smaller than max_value.
    for found_address in process.search_by_value_between(str, data_length, min_value, max_value):

        # Check if the found address is a target address.
        if found_address in target_addresses:
            addresses.remove(found_address)
            found += 1

        elif found_address in addresses:
            raise ValueError("Scanner returned the address of a clearly invalid string.")

    assert found / test_length >= 0.5


def test_close_process():
    # Try to close the process handle.
    assert process.close()
