# -*- coding: utf-8 -*-

from win32gui import FindWindow
from win32process import GetWindowThreadProcessId
import psutil

def get_process_id_by_process_name(process_name) -> int:

    """
    Get a process name and return its process ID.
    """

    for process in psutil.process_iter():
        if process.name() == process_name: return process.pid

def get_process_id_by_window_title(window_title) -> int:

    """
    Get a window title and return its process ID.
    """

    hwnd = FindWindow(None, window_title)
    return GetWindowThreadProcessId(hwnd)[1] if hwnd else 0

def pid_exists(pid) -> bool:

    """
    Check if the process ID exists.
    """

    return psutil.pid_exists(pid)
