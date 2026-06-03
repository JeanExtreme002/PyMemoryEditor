# -*- coding: utf-8 -*-
"""Sphinx configuration for PyMemoryEditor's documentation.

The docs use the MyST parser so every page can be written in Markdown, with
optional reStructuredText directives where they help (e.g. ``{toctree}``,
admonitions). The Read the Docs theme (``sphinx_rtd_theme``) provides the
familiar, friendly left-sidebar HTML build people expect from Python docs.
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

html_theme = "sphinx_rtd_theme"
html_title = "PyMemoryEditor"

html_theme_options = {
    # Brand-ish accent. The RTD theme defaults to its familiar blue; this just
    # tints the top sidebar block so it isn't the stock "#2980b9" everywhere.
    "logo_only": False,
    "collapse_navigation": False,
    "sticky_navigation": True,
    "navigation_depth": 3,
    "includehidden": True,
    "titles_only": False,
    "prev_next_buttons_location": "bottom",
    "style_external_links": True,
}

# Wire up the theme's native "Edit on GitHub" link (top-right of every page),
# plus the data the custom sidebar "Star on GitHub" call-to-action reads.
html_context = {
    "display_github": True,
    "github_user": "JeanExtreme002",
    "github_repo": "PyMemoryEditor",
    "github_version": "main",
    "conf_py_path": "/docs/",
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
