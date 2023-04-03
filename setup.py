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
        "License :: OSI Approved :: MIT License",
        "Intended Audience :: Developers",
        "Environment :: Win32 (MS Windows)",
        "Operating System :: Microsoft :: Windows",
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11"
    ]
)
