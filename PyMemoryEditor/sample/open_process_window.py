# -*- coding: utf-8 -*-

from tkinter import Label, Tk
from tkinter.ttk import Button, Entry
from typing import Optional

from PyMemoryEditor import OpenProcess
from PyMemoryEditor.errors import ProcessIDNotExistsError, ProcessNotFoundError
from PyMemoryEditor.process import AbstractProcess


class OpenProcessWindow(Tk):
    """
    Window for opening a process.
    """
    def __init__(self):
        super().__init__()
        self.__process = None

        self["bg"] = "white"

        self.title("PyMemoryEditor (Sample)")
        self.geometry("350x100")
        self.resizable(False, False)

        Label(self, text="Insert the PID or the process name:", bg="white", font=("Arial", 10)).pack(padx=20)

        self.__entry = Entry(self)
        self.__entry.pack(padx=50, fill="x", expand=True)

        Button(self, text="Open Process", command=self.__open_process).pack(pady=10)

        self.mainloop()

    def __open_process(self) -> None:
        """
        Open the process by the user input.
        """
        entry = self.__entry.get().strip()

        try:
            self.__process = OpenProcess(pid = int(entry))
            return self.destroy()

        except ValueError:
            try:
                self.__process = OpenProcess(process_name = entry)
                return self.destroy()
            except (ProcessIDNotExistsError, ProcessNotFoundError): pass
        except (ProcessIDNotExistsError, ProcessNotFoundError): pass

        self.__entry.delete(0, "end")
        self.__entry.insert(0, "Process not found.")

    def get_process(self) -> Optional[AbstractProcess]:
        """
        Return the opened process.
        """
        return self.__process
