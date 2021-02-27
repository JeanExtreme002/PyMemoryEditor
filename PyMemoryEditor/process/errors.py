# -*- coding: utf-8 -*-

class ProcessIDNotExistsError(Exception):

    def __init__(self, pid):
        self.__pid = pid

    def __str__(self):
        return "The process ID \"%i\" does not exist." % self.__pid

class ProcessNotFoundError(Exception):

    def __init__(self, process_name):
        self.__process_name = process_name

    def __str__(self):
        return "Could not find the process \"%s\"." % self.__process_name

class WindowNotFoundError(Exception):

    def __init__(self, window_title):
        self.__window_title = window_title

    def __str__(self):
        return "Could not find the window \"%s\"." % self.__window_title
