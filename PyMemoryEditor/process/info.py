# -*- coding: utf-8 -*-

from .errors import ProcessIDNotExistsError, ProcessNotFoundError
from .util import get_process_id_by_name, pid_exists


class ProcessInfo(object):
    """
    Class to save information of a process.
    """

    def __init__(self) -> None:
        self.__pid: int = -1
        self.__name: str = ""

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
    def name(self) -> str:
        return self.__name

    @name.setter
    def name(self, name: str) -> None:
        self.set_name(name)

    def set_name(
        self,
        name: str,
        *,
        case_sensitive: bool = True,
        exact_match: bool = True,
    ) -> None:
        pid = get_process_id_by_name(
            name,
            case_sensitive=case_sensitive,
            exact_match=exact_match,
        )
        if pid is None:
            raise ProcessNotFoundError(name)

        self.__pid = pid
        self.__name = name
