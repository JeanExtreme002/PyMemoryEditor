# -*- coding: utf-8 -*-

from main_application_window import ApplicationWindow
from open_process_window import OpenProcessWindow


def main(*args, **kwargs):
    open_process_window = OpenProcessWindow()
    process = open_process_window.get_process()

    if not process: return

    try: ApplicationWindow(process)
    finally: process.close()


if __name__ == "__main__":
    main()
