from .main_application_window import ApplicationWindow
from .open_process_window import OpenProcessWindow


def main(*args, **kwargs):
    open_process_window = OpenProcessWindow()
    process = open_process_window.get_process()

    if process:
        ApplicationWindow(process)
        process.close()


if __name__ == "__main__":
    main()
