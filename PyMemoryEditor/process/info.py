# -*- coding: utf-8 -*-

from .errors import ProcessIDNotExistsError, ProcessNotFoundError
from .util import get_process_id_by_process_name, pid_exists


class ProcessInfo(object):
    """
    Class to save information of a process.
    """

    def __init__(self) -> None:
        self.__pid: int = -1
        self.__process_name: str = ""

    @property
    def pid(self) -> int:
        return self.__pid

    @pid.setter
    def pid(self, pid: int) -> None:
        if not isinstance(pid, int):
            raise ValueError("The process ID must be an integer.")

        if pid < 0:
            raise ValueError("The process ID must be non-negative.")

        if not pid_exists(pid):
            raise ProcessIDNotExistsError(pid)

        self.__pid = pid

    @property
    def process_name(self) -> str:
        return self.__process_name

    @process_name.setter
    def process_name(self, process_name: str) -> None:
        self.set_process_name(process_name)

    def set_process_name(
        self,
        process_name: str,
        *,
        case_sensitive: bool = True,
        exact_match: bool = True,
    ) -> None:
        pid = get_process_id_by_process_name(
            process_name,
            case_sensitive=case_sensitive,
            exact_match=exact_match,
        )
        if pid is None:
            raise ProcessNotFoundError(process_name)

        self.__pid = pid
        self.__process_name = process_name
