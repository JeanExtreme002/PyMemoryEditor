from tkinter import DoubleVar, Frame, Label, Menu, Listbox, Scrollbar, Tk
from tkinter.ttk import Button, Entry, Menubutton, Progressbar

from PyMemoryEditor import ScanTypesEnum
from PyMemoryEditor.process import AbstractProcess


class ApplicationWindow(Tk):
    """
    Main window.
    """
    __comp_methods = {
        ScanTypesEnum.EXACT_VALUE: lambda x, y: x == y,
        ScanTypesEnum.NOT_EXACT_VALUE: lambda x, y: x != y,
        ScanTypesEnum.BIGGER_THAN: lambda x, y: x > y,
        ScanTypesEnum.SMALLER_THAN: lambda x, y: x < y,
    }

    def __init__(self, process: AbstractProcess):
        super().__init__()
        self.__process = process

        self.__scan_type = ScanTypesEnum.EXACT_VALUE
        self.__value = 0
        self.__value_type = int
        self.__value_length = 4
        self.__addresses = []

        self.__updating = False  # Indicate the application is updating the values of the found addresses.
        self.__scanning = False  # Indicate a scan has started.

        self["bg"] = "white"

        self.title(f"PyMemoryEditor (Sample) - Process ID: {process.pid}")
        self.geometry("900x400")

        self.protocol("WM_DELETE_WINDOW", self.__on_close)
        self.__close = False

        self.__addresses = []

        self.__build()
        self.mainloop()

    def __build(self):
        """
        Build the widgets of the window.
        """
        self.__entry_register_int = self.register(self.__validate_int_entry)
        self.__entry_register_hex = self.register(self.__validate_hex_entry)

        self.__input_frame_1 = Frame(self)
        self.__input_frame_1["bg"] = "white"
        self.__input_frame_1.pack(padx=5, fill="x", expand=True)

        self.__scan_input_frame = Frame(self.__input_frame_1)
        self.__scan_input_frame["bg"] = "white"
        self.__scan_input_frame.pack(fill="x", expand=True)

        # Value input.
        Label(self.__scan_input_frame, text="Value: ", bg="white", font=("Arial", 12)).pack(side="left")

        self.__value_entry = Entry(self.__scan_input_frame)
        self.__value_entry.pack(side="left", expand=True, fill="x")

        Label(self.__scan_input_frame, bg="white").pack(side="left")

        # Value length.
        Label(self.__scan_input_frame, text="Length (Bytes): ", bg="white", font=("Arial", 12)).pack(side="left")

        self.__length_entry = Entry(self.__scan_input_frame, width=5)
        self.__length_entry.insert(0, "4")
        self.__length_entry.config(validate="key", validatecommand=(self.__entry_register_int, "%P"))
        self.__length_entry.pack(side="left")

        Label(self.__scan_input_frame, bg="white").pack(side="left", padx=5)

        # Value type input.
        self.__type_menu_button = Menubutton(self.__scan_input_frame, width=10)
        self.__type_menu_button.pack(side="left")

        self.__type_menu = Menu(tearoff=0, bg="white")
        self.__type_menu.add_command(label="Boolean", command=lambda: self.__set_value_type(0))
        self.__type_menu.add_command(label="Integer", command=lambda: self.__set_value_type(1))
        self.__type_menu.add_command(label="Float", command=lambda: self.__set_value_type(2))
        self.__type_menu.add_command(label="String", command=lambda: self.__set_value_type(3))
        self.__type_menu_button.config(menu=self.__type_menu, text = "Integer")

        Label(self.__scan_input_frame, bg="white").pack(side="left", padx=10)

        # Scan type input.
        Label(self.__scan_input_frame, text="Scan Type: ", bg="white", font=("Arial", 12)).pack(side="left")

        self.__scan_menu_button = Menubutton(self.__scan_input_frame, width=15)
        self.__scan_menu_button.pack(side="left")

        self.__scan_menu = Menu(tearoff=0, bg="white")
        self.__scan_menu.add_command(label="Exact Value", command=lambda: self.__set_scan_type(0))
        self.__scan_menu.add_command(label="Not Exact Value", command=lambda: self.__set_scan_type(1))
        self.__scan_menu.add_command(label="Smaller Than", command=lambda: self.__set_scan_type(2))
        self.__scan_menu.add_command(label="Bigger Than", command=lambda: self.__set_scan_type(3))
        self.__scan_menu_button.config(menu=self.__scan_menu, text = "Exact Value")

        Label(self.__scan_input_frame, bg="white").pack(side="left", padx=5)

        # Buttons for scanning.
        self.__new_scan_button = Button(self.__scan_input_frame, text="First Scan", command=self.__new_scan)
        self.__new_scan_button.pack(side="left")

        Label(self.__scan_input_frame, bg="white").pack(side="left")

        self.__next_scan_button = Button(self.__scan_input_frame, command=self.__next_scan)
        self.__next_scan_button.pack(side="left")

        # Scanning process bar.
        self.__progress_var = DoubleVar()

        self.__progress_bar = Progressbar(self.__input_frame_1, variable=self.__progress_var)
        self.__progress_bar.pack(pady=5, fill="x", expand=True)

        # Label for counting and button for updating values.
        self.__result_frame = Frame(self)
        self.__result_frame["bg"] = "white"
        self.__result_frame.pack(padx=5, fill="both", expand=True)

        self.__count_frame = Frame(self.__result_frame)
        self.__count_frame["bg"] = "white"
        self.__count_frame.pack(pady=5, fill="x", expand=True)

        self.__count_label = Label(self.__count_frame, font=("Arial", 8), bg="white")
        self.__count_label.config(text="Start a new scan to find memory addresses.")
        self.__count_label.pack(side="left")

        Button(self.__count_frame, text="Update Values", command=self.__update_values).pack(side="right")

        # List with addresses and their values.
        self.__list_frame = Frame(self.__result_frame)
        self.__list_frame["bg"] = "white"
        self.__list_frame.pack(fill="both", expand=True)

        self.__scrollbar = Scrollbar(self.__list_frame, orient="vertical", command=self.__on_move_list_box)

        self.__address_list = Listbox(self.__list_frame, width=20)
        self.__address_list.bind("<MouseWheel>", self.__on_mouse_wheel)
        self.__address_list.bind("<<ListboxSelect>>", self.__select_address)
        self.__address_list.config(yscrollcommand = self.__scrollbar.set)
        self.__address_list.pack(side="left", fill="y")

        self.__value_list = Listbox(self.__list_frame)
        self.__value_list.bind("<MouseWheel>", self.__on_mouse_wheel)
        self.__value_list.bind("<<ListboxSelect>>", self.__select_value)
        self.__value_list.config(yscrollcommand = self.__scrollbar.set)
        self.__value_list.pack(side="left", fill="both", expand=True)

        self.__scrollbar.pack(side="left", fill="y")

        # Widgets for change the value of a memory address.
        self.__input_frame_2 = Frame(self)
        self.__input_frame_2["bg"] = "white"
        self.__input_frame_2.pack(padx=5, fill="x", expand=True)

        Label(self.__input_frame_2, text="Address:", bg="white").pack(side="left")

        self.__address_entry = Entry(self.__input_frame_2)
        self.__address_entry.config(validate="key", validatecommand=(self.__entry_register_hex, "%P"))
        self.__address_entry.pack(side="left")

        Label(self.__input_frame_2, bg="white").pack(side="left")

        Label(self.__input_frame_2, text="New Value:", bg="white").pack(side="left")

        self.__new_value_entry = Entry(self.__input_frame_2)
        self.__new_value_entry.pack(side="left", fill="x", expand=True)

        Button(self.__input_frame_2, text="Replace", command=self.__write_value).pack(side="left")

    def __new_scan(self):
        """
        Start a new seach at the whole memory of the process.
        """
        if self.__new_scan_button["text"].lower() == "scanning" or self.__updating: return
        self.__next_scan_button.config(text="")

        self.__addresses = []

        # If a scan is already in progress, clear all results and get everything ready for a new scan.
        if self.__scanning:
            self.__new_scan_button.config(text="First Scan")
            self.__count_label.config(text="Start a new scan to find memory addresses.")
            self.__address_list.delete(0, "end")
            self.__value_list.delete(0, "end")
            self.__progress_var.set(0)
            self.__scanning = False
            return

        # Get the inputs.
        value = self.__value_entry.get().strip()
        length = int(self.__length_entry.get())
        pytype = self.__value_type
        scan_type = self.__scan_type

        if not value or length == 0: return

        # Check if the value is valid for the selected value type.
        try:
            if str(pytype(value)) != value or (pytype is str and length < len(value)):
                raise ValueError()
        except:
            self.__value_entry.delete(0, "end")
            return self.__value_entry.insert(0, "Invalid value")

        # Start the scan.
        value = pytype(value)

        self.__value_length = length
        self.__value = value

        self.after(100, lambda: self.__start_scan(pytype, length, value, scan_type))

    def __next_scan(self):
        """
        Filter the found addresses.
        """
        self.__update_values(remove=True)

    def __on_close(self, *args):
        """
        Event to close the program graciously.
        """
        self.__close = True

        if self.__updating or self.__new_scan_button["text"].lower() == "scanning":
            self.update()
            return self.after(10, self.__on_close)

        self.destroy()

    def __on_move_list_box(self, *args):
        """
        Event to sync the listboxes.
        """
        self.__address_list.yview(*args)
        self.__value_list.yview(*args)

    def __on_mouse_wheel(self, event):
        """
        Event to sync the listboxes.
        """
        self.__address_list.yview("scroll", event.delta, "units")
        self.__value_list.yview("scroll", event.delta, "units")
        return "break"

    def __select_address(self, event):
        """
        Event to get the selected address and copy it.
        """
        selection = event.widget.curselection()
        if not selection: return

        address = self.__address_list.get(int(selection[0])).split(" ")[-1]
        if not address: return

        self.__address_entry.delete(0, "end")
        self.__address_entry.insert(0, address)

    def __select_value(self, event):
        """
        Event to get the selected value and copy it.
        """
        selection = event.widget.curselection()
        if not selection: return

        value = self.__value_list.get(int(selection[0]))[len("Value: "):]
        self.__new_value_entry.delete(0, "end")
        self.__new_value_entry.insert(0, value)

    def __start_scan(self, pytype, length, value, scan_type):
        """
        Search for a value on the whole memory of the process.
        """
        self.__new_scan_button.config(text="Scanning")
        self.update()

        self.__scanning = True
        self.__addresses = []

        for address, info in self.__process.search_by_value(pytype, length, value, scan_type, progress_information=True):
            if self.__close: break

            self.__address_list.insert("end", f"Addr: {hex(address)[2:].upper()}")
            self.__value_list.insert("end", f"Value: {value}")

            self.__progress_var.set(info["progress"] * 100)
            self.__addresses.append(address)
            self.update()

            self.__count_label.config(text=f"Found {len(self.__addresses)} addresses.")

        self.__new_scan_button.config(text="New Scan")
        self.__next_scan_button.config(text="Next Scan")
        self.__progress_var.set(100)

    def __set_scan_type(self, scan_type: int):
        """
        Method for the Menubutton to select a scan type.
        """
        # Allow select a new scan type only if program is not getting new addresses or updating their values.
        if self.__new_scan_button["text"].lower() == "scanning" or self.__updating: return

        self.__scan_type = [
            ScanTypesEnum.EXACT_VALUE,
            ScanTypesEnum.NOT_EXACT_VALUE,
            ScanTypesEnum.SMALLER_THAN,
            ScanTypesEnum.BIGGER_THAN,
        ][scan_type]

        text = " ".join(word.capitalize() for word in self.__scan_type.name.split("_"))
        self.__scan_menu_button.config(text=text)

    def __set_value_type(self, value_type: int):
        """
        Method for the Menubutton to select a value type.
        """
        if self.__scanning: return

        self.__value_type = [bool, int, float, str][value_type]
        self.__type_menu_button.config(text=["Boolean", "Integer", "Float", "String"][value_type])

    def __validate_int_entry(self, string):
        """
        Method to validate if an input is integer.
        """
        if self.__scanning: return False

        for char in string:
            if char not in "0123456789": return False
        return True

    def __validate_hex_entry(self, string):
        """
        Method to validate if an input is hexadecimal.
        """
        for char in string.upper():
            if char not in "0123456789ABCDEF": return False
        return True

    def __update_values(self, index = 0, *, remove = False, first_call = True):
        """
        Update the values of the found addresses. If "remove" is True, it will
        compare the current value in memory and remove the address from the
        results if the comparison is False.
        """
        if self.__updating and first_call: return  # Allow call the method once.

        # Return if user asked for closing the application.
        if self.__close:
            self.__updating = False
            return

        # Get the value to compare.
        if first_call:
            value = self.__value_entry.get().strip()

            try:
                if str(self.__value_type(value)) != value:
                    raise ValueError()
            except:
                self.__value_entry.delete(0, "end")
                return self.__value_entry.insert(0, "Invalid value")

            self.__value = self.__value_type(value)
            self.__progress_var.set(0)

        # Indicate the application is updating the values.
        self.__updating = True

        if index % 10 == 0: self.update()

        # Get the address from the list.
        try:
            address = self.__addresses[index]
        except:
            self.__updating = False

            self.__count_label.config(text=f"Found {len(self.__addresses)} addresses.")
            return self.__progress_var.set(100 if not first_call else 0)

        # Get the current value of the address.
        corrupted = False
        value = None

        try: value = self.__process.read_process_memory(address, self.__value_type, self.__value_length)
        except: corrupted = True

        # If "remove" is True, compare the value.
        if remove or corrupted:
            compare = self.__comp_methods[self.__scan_type]

            # Remove the address from the results.
            if corrupted or not compare(value, self.__value):
                self.__address_list.delete(index)
                self.__value_list.delete(index)
                self.__addresses.remove(address)
                index -= 1

        # Update the value at the listbox.
        else:
            self.__value_list.delete(index)
            self.__value_list.insert(index, f"Value: {value}")

        # Call the method again recursively
        if index % 10 == 0: self.__progress_var.set((index / len(self.__addresses)) * 100)
        self.after(5, lambda: self.__update_values(index + 1, remove=remove, first_call=False))

    def __write_value(self):
        """
        Change the value in memory of an address of the result list.
        """
        try:
            address = int(self.__address_entry.get().strip(), 16)
            if address not in self.__addresses: raise ValueError()
        except:
            self.__address_entry.delete(0, "end")
            return self.__address_entry.insert(0, "00000000")

        # Get the inputs.
        value = self.__new_value_entry.get()
        pytype = self.__value_type
        length = self.__value_length

        if not value or length == 0: return

        # Check if the value is valid for the selected value type.
        try:
            if str(pytype(value)) != value or (pytype is str and length < len(value)):
                raise ValueError()
        except:
            self.__new_value_entry.delete(0, "end")
            return self.__new_value_entry.insert(0, "Invalid value")

        # Write the new value.
        self.__process.write_process_memory(address, pytype, length, pytype(value))

