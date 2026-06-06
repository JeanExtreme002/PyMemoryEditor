#!/usr/bin/env python3
"""Render the GitHub social preview PNG from social-preview.html.

Works on macOS, Linux and Windows by locating a Chromium-based browser
(Chrome, Chromium or Edge) and driving it in headless screenshot mode.

This is a maintainer-only helper — it is intentionally kept out of the
published package (see the sdist/wheel excludes in ``pyproject.toml``).

Usage:
    python scripts/build_preview.py            # -> assets/social-preview.png (2560x1280, retina 2x)
    python scripts/build_preview.py --scale 1  # 1280x640 exact
    BROWSER=/path/to/chrome python scripts/build_preview.py   # force a specific binary
"""

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
HTML = REPO_ROOT / "assets" / "social-preview.html"
OUT = REPO_ROOT / "assets" / "social-preview.png"
WIDTH, HEIGHT = 1280, 640

# Candidate binaries per platform. The first one found is used.
CANDIDATES = {
    "darwin": [
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        "/Applications/Chromium.app/Contents/MacOS/Chromium",
        "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
    ],
    "linux": [
        "google-chrome", "google-chrome-stable", "chromium", "chromium-browser",
        "microsoft-edge", "microsoft-edge-stable",
    ],
    "win32": [
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
    ],
}


def find_browser() -> str:
    # Explicit override wins.
    override = os.environ.get("BROWSER")
    if override:
        if Path(override).exists() or shutil.which(override):
            return override
        sys.exit(f"BROWSER={override!r} not found.")

    platform = "win32" if sys.platform.startswith("win") else \
               "darwin" if sys.platform == "darwin" else "linux"

    for cand in CANDIDATES[platform]:
        # Absolute path that exists, or a name resolvable on PATH.
        if Path(cand).exists() or shutil.which(cand):
            return cand

    # Last resort: try common command names on PATH regardless of platform.
    for name in ("google-chrome", "chromium", "chrome", "msedge"):
        found = shutil.which(name)
        if found:
            return found

    sys.exit(
        "No Chrome/Chromium/Edge found. Install one, or set the BROWSER "
        "env var to its full path."
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--scale", type=int, default=2,
        help="device scale factor: 2 = retina 2560x1280 (default), 1 = exact 1280x640",
    )
    args = parser.parse_args()

    if not HTML.exists():
        sys.exit(f"Missing {HTML}")

    browser = find_browser()
    print(f"Using browser: {browser}")

    cmd = [
        browser,
        "--headless",
        "--disable-gpu",
        "--hide-scrollbars",
        f"--force-device-scale-factor={args.scale}",
        "--default-background-color=00000000",
        f"--window-size={WIDTH},{HEIGHT}",
        f"--screenshot={OUT}",
        HTML.as_uri(),
    ]

    result = subprocess.run(cmd)
    if result.returncode != 0 or not OUT.exists():
        sys.exit(f"Screenshot failed (exit {result.returncode}).")

    print(f"Wrote {OUT}  ({WIDTH * args.scale}x{HEIGHT * args.scale})")


if __name__ == "__main__":
    main()
