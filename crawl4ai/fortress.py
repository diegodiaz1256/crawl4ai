"""Fortress browser support.

Fortress is a Chromium build that corrects its fingerprint inside the C++
sources, so it presents as an ordinary Chrome install. crawl4ai normally
layers its own disguise on top (a fixed User-Agent, a generated sec-ch-ua
header, playwright-stealth and navigator_overrider JS patches, and launch flags
such as --disable-gpu). Each of those contradicts what Fortress reports and is
exactly what anti-bot sensors look for, so ``BrowserConfig(fortress=True)``
turns them all off and leaves the fingerprint to Fortress.
"""

import glob
import os
import re
import sys
from typing import List, Optional

FORTRESS_PATH_ENV = "FORTRESS_PATH"

# Where the tilion-fortress installer unpacks its builds:
# <cache>/tillion-fortress/<version>/<platform>/fortress-v<major>/chrome
# Only the Linux layout has been seen; elsewhere pass the path explicitly.


def _cache_root() -> str:
    if sys.platform == "win32":
        return os.environ.get("LOCALAPPDATA", os.path.expanduser("~\\AppData\\Local"))
    if sys.platform == "darwin":
        return os.path.expanduser("~/Library/Caches")
    return os.environ.get("XDG_CACHE_HOME", os.path.expanduser("~/.cache"))


def _version_key(path: str) -> tuple:
    parts = os.path.normpath(path).split(os.sep)
    version = parts[parts.index("tillion-fortress") + 1]
    return tuple(int(n) for n in re.findall(r"\d+", version))


def find_fortress_path(explicit: Optional[str] = None) -> str:
    """Return the Fortress executable: ``explicit``, then $FORTRESS_PATH, then
    the newest build in the tilion-fortress cache."""
    for candidate in (explicit, os.environ.get(FORTRESS_PATH_ENV)):
        if candidate:
            if not os.path.isfile(candidate):
                raise FileNotFoundError(f"Fortress executable not found at {candidate}")
            return candidate

    binary = "chrome.exe" if sys.platform == "win32" else "chrome"
    root = os.path.join(_cache_root(), "tillion-fortress")
    builds = [p for p in glob.glob(os.path.join(root, "*", "*", "fortress-v*", binary)) if os.path.isfile(p)]
    if not builds:
        raise FileNotFoundError(
            f"No Fortress build found under {root}. "
            f"Install Fortress, set {FORTRESS_PATH_ENV}, or pass BrowserConfig(fortress_path=...)."
        )
    return max(builds, key=_version_key)


def fortress_launch_flags() -> List[str]:
    """Launch flags that do not change what the page can observe.

    Deliberately absent from crawl4ai's usual set: --disable-gpu and friends
    (no WebGL is a headless tell), --disable-blink-features=AutomationControlled
    (Fortress already handles navigator.webdriver), --no-sandbox, and the
    background/IPC throttling switches that alter timing.
    """
    return [
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-dev-shm-usage",
        "--mute-audio",
    ]
