# -*- coding: utf-8 -*-
from enum import IntFlag


class ProcessOperationsEnum(IntFlag):
    """
    Bitmask of process access rights.

    Defined as ``IntFlag`` so that members can be combined directly with ``|``
    without unwrapping ``.value``. The ``.value`` attribute still works for
    callers that already use it.

    Reference:
      https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights
    """

    # Required to terminate a process using TerminateProcess.
    PROCESS_TERMINATE = 0x0001

    # Required to create a thread.
    PROCESS_CREATE_THREAD = 0x0002

    # Required to perform an operation on the address space of a process (see
    # VirtualProtectEx and WriteProcessMemory).
    PROCESS_VM_OPERATION = 0x0008

    # Required to read memory in a process using ReadProcessMemory.
    PROCESS_VM_READ = 0x0010

    # Required to write to memory in a process using WriteProcessMemory.
    PROCESS_VM_WRITE = 0x0020

    # Required to duplicate a handle using DuplicateHandle.
    PROCESS_DUP_HANDLE = 0x0040

    # Required to create a process.
    PROCESS_CREATE_PROCESS = 0x0080

    # Required to set memory limits using SetProcessWorkingSetSize.
    PROCESS_SET_QUOTA = 0x0100

    # Required to set certain information about a process, such as its
    # priority class (see SetPriorityClass).
    PROCESS_SET_INFORMATION = 0x0200

    # Required to retrieve certain information about a process, such as its
    # token, exit code, and priority class (see OpenProcessToken).
    PROCESS_QUERY_INFORMATION = 0x0400

    # Required to suspend or resume a process.
    PROCESS_SUSPEND_RESUME = 0x0800

    # Required to retrieve certain limited information about a process.
    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    PROCESS_SET_LIMITED_INFORMATION = 0x2000

    # All possible access rights for a process object on Windows Vista and
    # later. Pre-Vista (Windows XP / Server 2003) used 0x1F0FFF; PyMemoryEditor
    # targets Python 3.8+, which already required Vista+ as a baseline. The
    # `_has_all_access` helper checks against this canonical value.
    PROCESS_ALL_ACCESS = 0x1FFFFF
