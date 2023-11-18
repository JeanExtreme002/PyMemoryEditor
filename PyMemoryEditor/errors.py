from .process.errors import ProcessIDNotExistsError, ProcessNotFoundError


class ClosedProcess(Exception):
    def __str__(self):
        return "operation on closed process."
