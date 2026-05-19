# -*- coding: utf-8 -*-
import sys

from PyMemoryEditor import __version__


_MIN_TK_VERSION = 8.6


_TK_MISSING_HINTS = {
    "darwin": (
        "Your Python build doesn't include Tk. Reinstall with Tk support:\n"
        "  brew install tcl-tk\n"
        "  brew install python-tk@3.12     (if using Homebrew Python)\n"
        "  # or, for asdf/pyenv, rebuild Python after installing tcl-tk and\n"
        "  # setting PYTHON_CONFIGURE_OPTS=\"--with-tcltk-includes=... \\\n"
        "  #   --with-tcltk-libs=...\"\n"
        "  # or just download from https://www.python.org/downloads/macos/\n"
    ),
    "linux": (
        "Your Python build doesn't include Tk. Install the Tk bindings:\n"
        "  sudo apt install python3-tk        (Debian/Ubuntu)\n"
        "  sudo dnf install python3-tkinter   (Fedora)\n"
    ),
}

_TK_OLD_HINTS = {
    "darwin": (
        "macOS' system Python (/usr/bin/python3) ships with Tk 8.5, which is\n"
        "obsolete and buggy. Install a modern Python:\n"
        "  brew install python-tk@3.12   (Homebrew)\n"
        "  or download from https://www.python.org/downloads/macos/\n"
    ),
    "linux": (
        "Install up-to-date Tk bindings for your distro, e.g.:\n"
        "  sudo apt install python3-tk        (Debian/Ubuntu)\n"
        "  sudo dnf install python3-tkinter   (Fedora)\n"
    ),
}

_DEFAULT_FIX_HINT = "Upgrade Python from https://www.python.org/downloads/.\n"


def _platform_hint(table) -> str:
    key = "linux" if sys.platform.startswith("linux") else sys.platform
    return table.get(key, _DEFAULT_FIX_HINT)


def _abort_if_tk_unavailable():
    """
    Two failure modes the user hits in practice:

    1. `_tkinter` not built into Python (asdf/pyenv builds without Tcl/Tk
       headers; some minimal Linux images). `import tkinter` raises ImportError.
    2. Tk 8.5 (macOS' bundled /usr/bin/python3) has known bugs that make the
       sample unusable: trackpad scroll dead, Aqua theme broken, crashes on
       close.

    Either way the user benefits from a specific, actionable message instead
    of a confusing traceback or visual mess.

    Returns the imported `tkinter` module on success; aborts the process
    otherwise.
    """
    try:
        import tkinter
    except ImportError:
        sys.stderr.write(
            "PyMemoryEditor's Tk sample requires the `tkinter` module, "
            "which is missing from this Python build.\n\n"
            + _platform_hint(_TK_MISSING_HINTS)
        )
        sys.exit(2)

    if tkinter.TkVersion < _MIN_TK_VERSION:
        sys.stderr.write(
            "PyMemoryEditor's Tk sample requires Tk >= %.1f (current: %s).\n\n%s"
            % (_MIN_TK_VERSION, tkinter.TkVersion, _platform_hint(_TK_OLD_HINTS))
        )
        sys.exit(2)

    return tkinter


def _apply_native_theme(root) -> None:
    """Pick the ttk theme that looks closest to native on each platform."""
    from tkinter.ttk import Style

    style = Style(root)
    available = set(style.theme_names())

    preferred = {
        "darwin": "aqua",
        "win32": "vista",
    }.get(sys.platform, "clam")

    if preferred in available:
        style.theme_use(preferred)


def main(*_args, **_kwargs):
    if len(sys.argv) > 1 and sys.argv[1].strip() in ["--version", "-v"]:
        return print(__version__)

    _abort_if_tk_unavailable()

    # Late imports — these pull tkinter widgets, which can fail to initialize
    # on a half-installed Tk runtime. Aborting above gives a better message.
    from .main_application_window import ApplicationWindow
    from .open_process_window import OpenProcessWindow

    open_process_window = OpenProcessWindow()
    process = open_process_window.get_process()

    if not process: return

    try: ApplicationWindow(process)
    finally: process.close()


if __name__ == "__main__":
    main()
