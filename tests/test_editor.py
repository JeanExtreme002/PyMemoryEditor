from package import OpenProcess, version
from os import getpid
from typing import Optional
import ctypes
import platform
import random

print("Testing PyMemoryEditor version %s." % version)

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
    process = OpenProcess(pid = process_id)


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
    target_value = ctypes.create_string_buffer(generate_text(20).encode())
    address = ctypes.addressof(target_value)
    data_length = ctypes.sizeof(target_value)

    # Read the process memory and compare the result.
    result = process.read_process_memory(address, str, data_length)
    assert type(result) is str and result == str(target_value.value)


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

    target_value = ctypes.create_string_buffer(original_value)
    address = ctypes.addressof(target_value)
    data_length = ctypes.sizeof(target_value)

    # Write to the process memory and compare the result.
    process.write_process_memory(address, str, data_length, new_value)
    assert target_value.value != original_value and target_value.value == new_value


def test_close_process():
    # Try to close the process handle.
    assert process.close()
