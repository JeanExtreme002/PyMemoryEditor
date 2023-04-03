# -*- coding: utf-8 -*-
from enum import Enum


class ProcessOperations(Enum):
    """
    Enum with permissions and operations you can do to a process.
    """
    # Allocates memory charges (from the overall size of memory and the paging files on disk) for the specified reserved
    # memory pages. The function also guarantees that when the caller later initially accesses the memory, the contents will
    # be zero. Actual physical pages are not allocated unless/until the virtual addresses are actually accessed. To reserve
    # and commit pages in one step, call VirtualAllocEx with MEM_COMMIT | MEM_RESERVE. Attempting to commit a specific
    # address range by specifying MEM_COMMIT without MEM_RESERVE and a non-NULL lpAddress fails unless the entire range has
    # already been reserved. The resulting error code is ERROR_INVALID_ADDRESS. An attempt to commit a page that is already
    # committed does not cause the function to fail. This means that you can commit pages without first determining the
    # current commitment state of each page.
    # If lpAddress specifies an address within an enclave, flAllocationType must be MEM_COMMIT.
    MEM_COMMIT = 0x00001000

    # Reserves a range of the process's virtual address space without allocating any actual physical storage in memory or in
    # the paging file on disk. You commit reserved pages by calling VirtualAllocEx again with MEM_COMMIT. To reserve and
    # commit pages in one step, call VirtualAllocEx with MEM_COMMIT | MEM_RESERVE. Other memory allocation functions, such
    # as malloc and LocalAlloc, cannot use reserved memory until it has been released.
    MEM_RESERVE = 0x00002000

    # Indicates that data in the memory range specified by lpAddress and dwSize is no longer of interest. The pages should
    # not be read from or written to the paging file. However, the memory block will be used again later, so it should not be
    # decommitted. This value cannot be used with any other value. Using this value does not guarantee that the range operated
    # on with MEM_RESET will contain zeros. If you want the range to contain zeros, decommit the memory and then recommit it.
    # When you use MEM_RESET, the VirtualAllocEx function ignores the value of fProtect. However, you must still set fProtect
    # to a valid protection value, such as PAGE_NOACCESS. VirtualAllocEx returns an error if you use MEM_RESET and the range
    # of memory is mapped to a file. A shared view is only acceptable if it is mapped to a paging file.
    MEM_RESET = 0x00080000

    # MEM_RESET_UNDO should only be called on an address range to which MEM_RESET was successfully applied earlier. It
    # indicates that the data in the specified memory range specified by lpAddress and dwSize is of interest to the caller
    # and attempts to reverse the effects of MEM_RESET. If the function succeeds, that means all data in the specified address
    # range is intact. If the function fails, at least some of the data in the address range has been replaced with zeroes.
    # This value cannot be used with any other value. If MEM_RESET_UNDO is called on an address range which was not MEM_RESET
    # earlier, the behavior is undefined. When you specify MEM_RESET, the VirtualAllocEx function ignores the value of
    # flProtect. However, you must still set flProtect to a valid protection value, such as PAGE_NOACCESS.
    # Windows Server 2008 R2, Windows 7, Windows Server 2008, Windows Vista, Windows Server 2003 and Windows XP:
    # The MEM_RESET_UNDO flag is not supported until Windows 8 and Windows Server 2012.
    MEM_RESET_UNDO = 0x1000000

    # Allocates memory using large page support. The size and alignment must be a multiple of the large-page minimum. To
    # obtain this value, use the GetLargePageMinimum function.
    # If you specify this value, you must also specify MEM_RESERVE and MEM_COMMIT.
    MEM_LARGE_PAGES = 0x20000000

    # Reserves an address range that can be used to map Address Windowing Extensions (AWE) pages. This value must be used
    # with MEM_RESERVE and no other values.
    MEM_PHYSICAL = 0x00400000

    # Allocates memory at the highest possible address. This can be slower than regular allocations, especially when there
    # are many allocations.
    MEM_TOP_DOWN = 0x00100000

    # Enables execute access to the committed region of pages. An attempt to write to the committed
    # region results in an access violation. This flag is not supported by the CreateFileMapping function.
    PAGE_EXECUTE = 0x10

    # Enables execute or read-only access to the committed region of pages. An attempt to write to the committed region
    # results in an access violation. Windows Server 2003 and Windows XP: This attribute is not supported by the
    # CreateFileMapping function until Windows XP with SP2 and Windows Server 2003 with SP1.
    PAGE_EXECUTE_READ = 0x20

    # Enables execute, read-only, or read/write access to the committed region of pages. Windows Server 2003 and
    # Windows XP: This attribute is not supported by the CreateFileMapping function until Windows XP with SP2
    # and Windows Server 2003 with SP1.
    PAGE_EXECUTE_READWRITE = 0x40

    # Enables execute, read-only, or copy-on-write access to a mapped view of a file mapping object. An attempt to
    # write to a committed copy-on-write page results in a private copy of the page being made for the process. The
    # private page is marked as PAGE_EXECUTE_READWRITE, and the change is written to the new page. This flag is not
    # supported by the VirtualAlloc or VirtualAllocEx functions. Windows Vista, Windows Server 2003 and Windows XP:
    # This attribute is not supported by the CreateFileMapping function until Windows Vista with SP1 and Windows Server 2008.
    PAGE_EXECUTE_WRITECOPY = 0x80

    # Disables all access to the committed region of pages. An attempt to read from, write to, or execute the committed
    # region results in an access violation. This flag is not supported by the CreateFileMapping function.
    PAGE_NOACCESS = 0x01

    # Enables read-only access to the committed region of pages. An attempt to write to the committed region results in
    # an access violation. If Data Execution Prevention is enabled, an attempt to execute code in the committed region
    # results in an access violation.
    PAGE_READONLY = 0x02

    # Enables read-only or read/write access to the committed region of pages. If Data Execution Prevention is enabled,
    # attempting to execute code in the committed region results in an access violation.
    PAGE_READWRITE = 0x04

    # Enables read-only or copy-on-write access to a mapped view of a file mapping object. An attempt to write to a
    # committed copy-on-write page results in a private copy of the page being made for the process. The private page
    # is marked as PAGE_READWRITE, and the change is written to the new page. If Data Execution Prevention is enabled,
    # attempting to execute code in the committed region results in an access violation. This flag is not supported by
    # the VirtualAlloc or VirtualAllocEx functions.
    PAGE_WRITECOPY = 0x08

    # Sets all locations in the pages as invalid targets for CFG. Used along with any execute page protection like
    # PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE and PAGE_EXECUTE_WRITECOPY. Any indirect call to locations
    # in those pages will fail CFG checks and the process will be terminated. The default behavior for executable pages
    # allocated is to be marked valid call targets for CFG. This flag is not supported by the VirtualProtect or
    # CreateFileMapping functions.
    PAGE_TARGETS_INVALID = 0x40000000

    # Pages in the region will not have their CFG information updated while the protection changes for VirtualProtect.
    # For example, if the pages in the region was allocated using PAGE_TARGETS_INVALID, then the invalid information
    # will be maintained while the page protection changes. This flag is only valid when the protection changes to an
    # executable type like PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE and PAGE_EXECUTE_WRITECOPY. The default
    # behavior for VirtualProtect protection change to executable is to mark all locations as valid call targets for CFG.
    PAGE_TARGETS_NO_UPDATE = 0x40000000

    # Pages in the region become guard pages. Any attempt to access a guard page causes the system to raise a
    # STATUS_GUARD_PAGE_VIOLATION exception and turn off the guard page status. Guard pages thus act as a one-time access
    # alarm. For more information, see Creating Guard Pages. When an access attempt leads the system to turn off guard page
    # status, the underlying page protection takes over. If a guard page exception occurs during a system service, the
    # service typically returns a failure status indicator. This value cannot be used with PAGE_NOACCESS. This flag is not
    # supported by the CreateFileMapping function.
    PAGE_GUARD = 0x100

    # Sets all pages to be non-cachable. Applications should not use this attribute except when explicitly required for a
    # device. Using the interlocked functions with memory that is mapped with SEC_NOCACHE can result in an
    # EXCEPTION_ILLEGAL_INSTRUCTION exception. The PAGE_NOCACHE flag cannot be used with the PAGE_GUARD, PAGE_NOACCESS, or
    # PAGE_WRITECOMBINE flags. The PAGE_NOCACHE flag can be used only when allocating private memory with the VirtualAlloc,
    # VirtualAllocEx, or VirtualAllocExNuma functions. To enable non-cached memory access for shared memory, specify the
    # SEC_NOCACHE flag when calling the CreateFileMapping function.
    PAGE_NOCACHE = 0x200

    # Sets all pages to be write-combined. Applications should not use this attribute except when explicitly required for a
    # device. Using the interlocked functions with memory that is mapped as write-combined can result in an
    # EXCEPTION_ILLEGAL_INSTRUCTION exception. The PAGE_WRITECOMBINE flag cannot be specified with the PAGE_NOACCESS,
    # PAGE_GUARD, and PAGE_NOCACHE flags. The PAGE_WRITECOMBINE flag can be used only when allocating private memory with
    # the VirtualAlloc, VirtualAllocEx, or VirtualAllocExNuma functions. To enable write-combined memory access for shared
    # memory, specify the SEC_WRITECOMBINE flag when calling the CreateFileMapping function. Windows Server 2003 and
    # Windows XP: This flag is not supported until Windows Server 2003 with SP1.
    PAGE_WRITECOMBINE = 0x400

    # Required to delete the object.
    DELETE = 0x00010000

    # Required to read information in the security descriptor for the object, not including the
    # information in the SACL. To read or write the SACL, you must request the ACCESS_SYSTEM_SECURITY
    # access right. For more information, see SACL Access Right.
    READ_CONTROL = 0x00020000

    # The right to use the object for synchronization. This enables a thread to wait until the object
    # is in the signaled state.
    SYNCHRONIZE = 0x00100000

    # Required to modify the DACL in the security descriptor for the object.
    WRITE_DAC = 0x00040000

    # Required to change the owner in the security descriptor for the object.
    WRITE_OWNER = 0x00080000

    # All possible access rights for a process object.Windows Server 2003 and Windows XP: The size of
    # the PROCESS_ALL_ACCESS flag increased on Windows Server 2008 and Windows Vista. If an application
    # compiled for Windows Server 2008 and Windows Vista is run on Windows Server 2003 or Windows XP,
    # the PROCESS_ALL_ACCESS flag is too large and the function specifying this flag fails with
    # ERROR_ACCESS_DENIED. To avoid this problem, specify the minimum set of access rights required for
    # the operation. If PROCESS_ALL_ACCESS must be used, set _WIN32_WINNT to the minimum operating
    # system targeted by your application (for example, #define _WIN32_WINNT _WIN32_WINNT_WINXP). For
    # more information, see Using the Windows Headers.
    PROCESS_ALL_ACCESS = 0x1f0fff

    # Required to create a process.
    PROCESS_CREATE_PROCESS = 0x0080

    # Required to create a thread.
    PROCESS_CREATE_THREAD = 0x0002

    # Required to duplicate a handle using DuplicateHandle.
    PROCESS_DUP_HANDLE = 0x0040

    # Required to retrieve certain information about a process, such as its token, exit code, and priority
    # class (see OpenProcessToken).
    PROCESS_QUERY_INFORMATION = 0x0400

    # Required to retrieve certain information about a process (see GetExitCodeProcess, GetPriorityClass,
    # IsProcessInJob, QueryFullProcessImageName). A handle that has the PROCESS_QUERY_INFORMATION access right
    # is automatically granted PROCESS_QUERY_LIMITED_INFORMATION.Windows Server 2003 and Windows XP: This
    # access right is not supported.
    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000

    # Required to set certain information about a process, such as its priority class (see SetPriorityClass).
    PROCESS_SET_INFORMATION = 0x0200
    PROCESS_SET_LIMITED_INFORMATION = 0x2000

    # Required to set memory limits using SetProcessWorkingSetSize.
    PROCESS_SET_QUOTA = 0x0100

    # Required to suspend or resume a process.
    PROCESS_SUSPEND_RESUME = 0x0800

    # Required to terminate a process using TerminateProcess.
    PROCESS_TERMINATE = 0x0800

    # Required to perform an operation on the address space of a process (see VirtualProtectEx and WriteProcessMemory).
    PROCESS_VM_OPERATION = 0x0008

    # Required to read memory in a process using ReadProcessMemory.
    PROCESS_VM_READ = 0x0010

    # Required to write to memory in a process using WriteProcessMemory.
    PROCESS_VM_WRITE = 0x0020

    # The thread runs immediately after creation.
    EXECUTE_IMMEDIATELY = 0x00000000

    # The thread is created in a suspended state, and does not run until the ResumeThread function is called.
    CREATE_SUSPENDED = 0x00000004

    # The dwStackSize parameter specifies the initial reserve size of the stack.
    # If this flag is not specified, dwStackSize specifies the commit size.
    STACK_SIZE_PARAM_IS_A_RESERVATION = 0x00010000
