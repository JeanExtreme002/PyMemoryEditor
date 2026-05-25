# -*- coding: utf-8 -*-
"""
App icon loader.

The icon is shipped as a single SVG under ``PyMemoryEditor/app/assets/`` and
rasterized at several common sizes at runtime with QSvgRenderer. We don't
rely on Qt's SVG image plugin being registered (which can fail on minimal
PySide6 deployments) — rendering directly into QPixmaps works regardless,
and pre-seeding the QIcon at multiple sizes gives crisp results in window
chrome, taskbars and HiDPI alt-tab thumbnails.
"""
from importlib import resources
from typing import Optional

from PySide6.QtCore import QByteArray, Qt
from PySide6.QtGui import QIcon, QPainter, QPixmap
from PySide6.QtSvg import QSvgRenderer


_ICON: Optional[QIcon] = None

# Sizes covering taskbars (16/24/32), title bars (48), dock icons (64/128)
# and HiDPI scaling headroom (256/512).
_SIZES = (16, 24, 32, 48, 64, 128, 256, 512)


def app_icon() -> QIcon:
    """Return the cached PyMemoryEditor app icon."""
    global _ICON
    if _ICON is not None:
        return _ICON

    svg_bytes = (
        resources.files("PyMemoryEditor.app")
        .joinpath("assets", "icon.svg")
        .read_bytes()
    )
    renderer = QSvgRenderer(QByteArray(svg_bytes))

    icon = QIcon()
    for size in _SIZES:
        pix = QPixmap(size, size)
        pix.fill(Qt.transparent)
        painter = QPainter(pix)
        renderer.render(painter)
        painter.end()
        icon.addPixmap(pix)

    _ICON = icon
    return _ICON
