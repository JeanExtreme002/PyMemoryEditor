# -*- coding: utf-8 -*-

from PyMemoryEditor import __version__
from setuptools import setup, find_packages

with open("README.md") as file:
    README = file.read()

setup(
    name = "PyMemoryEditor",
    version = __version__,
    description = "Process memory reader and writer.",
    long_description = README,
    long_description_content_type = "text/markdown",
    author = "Jean Loui Bernard Silva de Jesus",
    url = "https://github.com/JeanExtreme002/PyMemoryEditor",
    license = "MIT",
    keywords = "memory writer reader",
    packages = ["PyMemoryEditor", "PyMemoryEditor.process", "PyMemoryEditor.win32"],
    install_requires = ["pywin32", "psutil"],
    classifiers = [
        "Operating System :: Microsoft :: Windows",
        "Operating System :: Microsoft :: Windows :: Windows 7",
        "Operating System :: Microsoft :: Windows :: Windows 8",
        "Operating System :: Microsoft :: Windows :: Windows 8.1",
        "Operating System :: Microsoft :: Windows :: Windows 10",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8"
    ]
)
