# -*- coding: utf-8 -*-
"""Sphinx configuration for PyMemoryEditor's documentation.

The docs use the MyST parser so every page can be written in Markdown, with
optional reStructuredText directives where they help (e.g. ``{toctree}``,
admonitions). The Furo theme provides a modern dark/light HTML build.
"""

import os
import sys
from datetime import datetime

# Make the package importable for autodoc-style cross references.
sys.path.insert(0, os.path.abspath(".."))

# -- Project information -----------------------------------------------------

project = "PyMemoryEditor"
author = "Jean Loui Bernard Silva de Jesus"
copyright = f"{datetime.now().year}, {author}"

try:
    from PyMemoryEditor import __version__ as release
except Exception:  # pragma: no cover - docs can build without the package installed
    release = "2.0.0"

version = ".".join(release.split(".")[:2])

# -- General configuration ---------------------------------------------------

extensions = [
    "myst_parser",
    "sphinx.ext.autodoc",
    "sphinx.ext.napoleon",
    "sphinx.ext.intersphinx",
    "sphinx.ext.viewcode",
    "sphinx_copybutton",
    "sphinx_design",
]

source_suffix = {
    ".md": "markdown",
    ".rst": "restructuredtext",
}

master_doc = "index"

templates_path = ["_templates"]
exclude_patterns = ["_build", "Thumbs.db", ".DS_Store"]

# -- MyST configuration ------------------------------------------------------

myst_enable_extensions = [
    "colon_fence",
    "deflist",
    "fieldlist",
    "html_image",
    "html_admonition",
    "linkify",
    "replacements",
    "smartquotes",
    "substitution",
    "tasklist",
]

myst_heading_anchors = 3

# -- HTML output -------------------------------------------------------------

html_theme = "furo"
html_title = "PyMemoryEditor"

html_theme_options = {
    "sidebar_hide_name": False,
    "navigation_with_keys": True,
    "source_repository": "https://github.com/JeanExtreme002/PyMemoryEditor/",
    "source_branch": "main",
    "source_directory": "docs/",
    "light_css_variables": {
        "color-brand-primary": "#8A2BE2",
        "color-brand-content": "#8A2BE2",
    },
    "dark_css_variables": {
        "color-brand-primary": "#B57AFF",
        "color-brand-content": "#B57AFF",
    },
}

html_static_path = ["_static"]

# Logo and favicon resolved from the bundled SVG icon.
html_logo = "../PyMemoryEditor/app/assets/icon.svg"
html_favicon = "../PyMemoryEditor/app/assets/icon.svg"

# -- Intersphinx mappings ----------------------------------------------------

intersphinx_mapping = {
    "python": ("https://docs.python.org/3", None),
}

# -- Autodoc -----------------------------------------------------------------

autodoc_default_options = {
    "members": True,
    "undoc-members": False,
    "show-inheritance": True,
}
autodoc_member_order = "bysource"
autoclass_content = "both"

# -- copybutton --------------------------------------------------------------

copybutton_prompt_text = r">>> |\.\.\. |\$ "
copybutton_prompt_is_regexp = True
