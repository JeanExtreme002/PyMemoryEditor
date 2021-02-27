# -*- coding: utf-8 -*-

from .errors import ProcessIDNotExistsError, ProcessNotFoundError, WindowNotFoundError
from .util import get_process_id_by_process_name, get_process_id_by_window_title, pid_exists

class Process(object):

    __pid = 0
    __process_name = ""
    __window_title = ""

    @property
    def pid(self):
        return self.__pid

    @pid.setter
    def pid(self, pid):

        # Check if the value is an integer.
        if not isinstance(pid, int):
            raise ValueError("The process ID must be an integer.")

        # Check if the PID exists and instantiate it.
        if pid_exists(pid): self.__pid = pid
        else: raise ProcessIDNotExistsError(pid)

    @property
    def process_name(self):
        return self.__process_name

    @process_name.setter
    def process_name(self, process_name):

        # Get the process ID.
        pid = get_process_id_by_process_name(process_name)
        if not pid: raise ProcessNotFoundError(process_name)

        # Set the PID and process name.
        self.__pid = pid
        self.__process_name = process_name

    @property
    def window_title(self):
        return self.__window_title

    @window_title.setter
    def window_title(self, window_title):

        # Get the process ID.
        pid = get_process_id_by_window_title(window_title)
        if not pid: raise WindowNotFoundError(window_title)

        # Set the PID and the window title.
        self.__pid = pid
        self.__window_title = window_title
