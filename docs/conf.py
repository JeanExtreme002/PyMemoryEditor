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
        "color-brand-primary": "#0D9488",
        "color-brand-content": "#0D9488",
    },
    "dark_css_variables": {
        "color-brand-primary": "#2DD4BF",
        "color-brand-content": "#2DD4BF",
    },
    # Persistent GitHub call-to-action, pinned to the sidebar footer on every page.
    "footer_icons": [
        {
            "name": "GitHub",
            "url": "https://github.com/JeanExtreme002/PyMemoryEditor",
            "html": """
                <svg stroke="currentColor" fill="currentColor" stroke-width="0" viewBox="0 0 16 16">
                    <path fill-rule="evenodd" d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z"></path>
                </svg>
            """,
            "class": "",
        },
    ],
}

html_static_path = ["_static"]
html_css_files = ["custom.css"]

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
