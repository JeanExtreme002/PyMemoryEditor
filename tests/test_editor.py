from package import OpenProcess, version
from os import getpid
import ctypes
import random

print("Testing PyMemoryEditor version %s." % version)

process_id = getpid()
process = None


def generate_text(size):
    # Return a random text.
    return "".join([chr(random.randint(ord("A"), ord("Z"))) for letter in range(size)])


def test_open_process():
    global process

    # Open the process to write and read the process memory.
    process = OpenProcess(pid = process_id)


def test_read_float():
    # Get a random value to compare the result.
    target_value = ctypes.c_double(random.random())
    address = ctypes.addressof(target_value)
    data_length = ctypes.sizeof(target_value)

    # Read the process memory and compare the result.
    result = process.read_process_memory(address, float, data_length)
    assert result == target_value.value


def test_read_int():
    # Get a random value to compare the result.
    target_value = ctypes.c_int(random.randint(0, 10000))
    address = ctypes.addressof(target_value)
    data_length = ctypes.sizeof(target_value)

    # Read the process memory and compare the result.
    result = process.read_process_memory(address, int, data_length)
    assert result == target_value.value


def test_read_string():
    # Get a random text to compare the result.
    target_value = ctypes.create_string_buffer(generate_text(20).encode())
    address = ctypes.addressof(target_value)
    data_length = ctypes.sizeof(target_value)

    # Read the process memory and compare the result.
    result = process.read_process_memory(address, str, data_length)
    assert result == target_value.value


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
    new_value = original_value[::-1]

    target_value = ctypes.create_string_buffer(original_value)
    address = ctypes.addressof(target_value)
    data_length = ctypes.sizeof(target_value)

    # Write to the process memory and compare the result.
    process.write_process_memory(address, str, data_length, new_value)
    assert target_value.value != original_value and target_value.value == new_value


def test_close_process():
    # Try to close the process handle.
    assert process.close()
