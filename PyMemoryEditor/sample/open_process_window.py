# -*- coding: utf-8 -*-

from tkinter import Frame, Label, Listbox, Scrollbar, Tk
from tkinter.ttk import Button, Entry
from typing import Optional

from PyMemoryEditor import OpenProcess
from PyMemoryEditor.errors import ProcessIDNotExistsError, ProcessNotFoundError
from PyMemoryEditor.process import AbstractProcess

import psutil


class OpenProcessWindow(Tk):
    """
    Window for opening a process.
    """
    def __init__(self):
        super().__init__()
        self.__process = None

        self["bg"] = "white"

        self.title("PyMemoryEditor (Sample)")
        self.geometry("400x350")
        self.resizable(False, False)

        Label(self, text="Insert the PID or the process name:", bg="white", font=("Arial", 10)).pack(padx=20, pady=5)

        self.__list_frame = Frame(self)
        self.__list_frame["bg"] = "white"
        self.__list_frame.pack(padx=50, fill="both", expand=True)

        self.__scrollbar = Scrollbar(self.__list_frame, orient="vertical", command=self.__on_move_list_box)

        self.__process_list = Listbox(self.__list_frame, width=40)
        self.__process_list.bind("<<ListboxSelect>>", self.__select_process)
        self.__process_list.config(yscrollcommand=self.__scrollbar.set)
        self.__process_list.pack(side="left", fill="both", expand=True)

        self.__scrollbar.pack(side="left", fill="y")

        self.__entry = Entry(self)
        self.__entry.pack(padx=50, fill="x", expand=True)

        Button(self, text="Open Process", command=self.__open_process).pack(pady=10)

        self.__update_process_list()
        self.mainloop()

    def __on_move_list_box(self, *args) -> None:
        """
        Event to sync the listbox.
        """
        self.__process_list.yview(*args)

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

    def __select_process(self, event) -> None:
        """
        Event to get the selected address and copy it.
        """
        selection = event.widget.curselection()
        if not selection: return

        process = self.__process_list.get(int(selection[0])).split("(")[-1].replace(")", "")
        if not process: return

        self.__entry.delete(0, "end")
        self.__entry.insert(0, process)

    def __update_process_list(self):
        """
        Update the process list with new processes.
        """
        self.__process_list.delete(0, "end")

        processes = sorted([(process.name(), process.pid) for process in psutil.process_iter()], key=lambda x: x[0])

        for name, pid in processes:
            if not name.replace(" ", ""): continue
            self.__process_list.insert("end", "{} ({})".format(name, pid))

    def get_process(self) -> Optional[AbstractProcess]:
        """
        Return the opened process.
        """
        return self.__process
