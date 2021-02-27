# PyMemoryEditor
Read and write values in memory in Python 3 easily.

# Basic Usage

```
from PyMemoryEditor import OpenProcess

process_name = "example.exe"
address = 0x0005000C

with OpenProcess(process_name = process_name) as process:

    # Getting value from the process memory.
    value = process.read_process_memory(address, int, 4)
    
    # Writing to the process memory.
    process.write_process_memory(address, int, 4, value + 7)
```
