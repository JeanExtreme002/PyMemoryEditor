class ClosedProcess(Exception):
    def __str__(self):
        return "operation on closed process."