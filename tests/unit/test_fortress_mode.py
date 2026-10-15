"""BrowserConfig(fortress=True): launch the Fortress browser and leave its
fingerprint alone (no UA/sec-ch-ua override, no JS stealth, no observable
launch flags)."""

import asyncio
import os
import stat

import pytest

from crawl4ai import BrowserConfig
from crawl4ai.browser_manager import ManagedBrowser
from crawl4ai.fortress import FORTRESS_PATH_ENV, find_fortress_path, fortress_launch_flags


def _fake_build(root, version):
    d = root / "tillion-fortress" / version / "linux-x64" / f"fortress-v{version.split('.')[0]}"
    d.mkdir(parents=True)
    exe = d / "chrome"
    exe.write_text("#!/bin/sh\n")
    exe.chmod(exe.stat().st_mode | stat.S_IXUSR)
    return str(exe)


# ── config ─────────────────────────────────────────────────────────────


def test_fortress_drops_ua_and_client_hints():
    bc = BrowserConfig(fortress=True, headers={"User-Agent": "x", "sec-ch-ua": "y", "Accept-Language": "es"})
    assert bc.user_agent is None
    assert bc.browser_hint is None
    assert bc.headers == {"Accept-Language": "es"}
    assert bc.use_managed_browser is True


def test_default_config_still_sets_ua_and_client_hints():
    bc = BrowserConfig()
    assert bc.user_agent
    assert "sec-ch-ua" in bc.headers


def test_fortress_disables_js_stealth_with_warning():
    with pytest.warns(UserWarning, match="enable_stealth"):
        bc = BrowserConfig(fortress=True, enable_stealth=True)
    assert bc.enable_stealth is False


def test_fortress_ignores_explicit_ua_with_warning():
    with pytest.warns(UserWarning, match="user_agent"):
        bc = BrowserConfig(fortress=True, user_agent="Mozilla/5.0 custom", user_agent_mode="random")
    assert bc.user_agent is None
    assert bc.user_agent_mode == ""


def test_fortress_uses_managed_browser_not_persistent_context():
    bc = BrowserConfig(fortress=True, use_persistent_context=True, user_data_dir="/tmp/p")
    assert bc.use_managed_browser is True
    assert bc.use_persistent_context is False
    assert bc.user_data_dir == "/tmp/p"


def test_fortress_requires_chromium():
    with pytest.raises(ValueError, match="chromium"):
        BrowserConfig(fortress=True, browser_type="firefox")


def test_fortress_survives_clone():
    bc = BrowserConfig(fortress=True, fortress_path="/opt/fortress/chrome").clone(headless=False)
    assert bc.fortress is True
    assert bc.fortress_path == "/opt/fortress/chrome"
    assert bc.user_agent is None
    assert "sec-ch-ua" not in bc.headers


# ── executable lookup ──────────────────────────────────────────────────


def test_find_picks_newest_cached_build(tmp_path, monkeypatch):
    monkeypatch.delenv(FORTRESS_PATH_ENV, raising=False)
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
    _fake_build(tmp_path, "153.0.8010.36")
    newest = _fake_build(tmp_path, "153.0.8010.100")
    _fake_build(tmp_path, "99.0.1.1")
    assert find_fortress_path() == newest


def test_find_prefers_explicit_then_env(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
    cached = _fake_build(tmp_path, "153.0.8010.36")
    other = tmp_path / "other-chrome"
    other.write_text("")
    monkeypatch.setenv(FORTRESS_PATH_ENV, str(other))
    assert find_fortress_path() == str(other)
    assert find_fortress_path(cached) == cached


def test_find_errors_clearly(tmp_path, monkeypatch):
    monkeypatch.delenv(FORTRESS_PATH_ENV, raising=False)
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
    with pytest.raises(FileNotFoundError, match="No Fortress build"):
        find_fortress_path()
    with pytest.raises(FileNotFoundError, match="not found at"):
        find_fortress_path(str(tmp_path / "missing"))


# ── launch args ────────────────────────────────────────────────────────


def test_managed_launch_uses_fortress_binary_and_quiet_flags(tmp_path):
    exe = _fake_build(tmp_path, "153.0.8010.36")
    bc = BrowserConfig(fortress=True, fortress_path=exe, headless=True, debugging_port=9333)
    mb = ManagedBrowser(browser_config=bc)
    mb.user_data_dir = str(tmp_path / "profile")
    args = asyncio.run(mb._get_browser_args())

    assert args[0] == exe
    assert "--remote-debugging-port=9333" in args
    assert "--headless=new" in args
    for flag in fortress_launch_flags():
        assert flag in args
    for tell in ("--disable-gpu", "--no-sandbox", "--disable-blink-features=AutomationControlled"):
        assert tell not in args


def test_managed_launch_without_fortress_is_unchanged(monkeypatch):
    bc = BrowserConfig(headless=True)
    mb = ManagedBrowser(browser_config=bc)
    mb.user_data_dir = "/tmp/p"

    async def fake_path():
        return "chromium"

    monkeypatch.setattr(mb, "_get_browser_path", fake_path)
    args = asyncio.run(mb._get_browser_args())
    assert "--disable-blink-features=AutomationControlled" in args


# ── end to end (needs a real Fortress build) ───────────────────────────


def _fortress_available():
    try:
        find_fortress_path()
        return True
    except FileNotFoundError:
        return False


@pytest.mark.skipif(not _fortress_available(), reason="Fortress not installed")
def test_fortress_keeps_its_own_fingerprint():
    """Even with magic=True (which normally swaps the UA and injects
    navigator_overrider), the page sees Fortress's own fingerprint."""
    import http.server
    import threading

    from crawl4ai import AsyncWebCrawler, CacheMode, CrawlerRunConfig

    seen = {}

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            seen.update({k.lower(): v for k, v in self.headers.items()})
            body = b"<html><body><p id=fp></p><script>document.getElementById('fp').textContent = JSON.stringify({ua: navigator.userAgent, wd: navigator.webdriver})</script></body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{server.server_address[1]}/"

    async def run():
        bc = BrowserConfig(fortress=True, headless=True, debugging_port=9341, verbose=False)
        run_cfg = CrawlerRunConfig(cache_mode=CacheMode.BYPASS, magic=True)
        async with AsyncWebCrawler(config=bc) as crawler:
            return await crawler.arun(url, config=run_cfg)

    try:
        r = asyncio.run(run())
    finally:
        server.shutdown()

    assert r.success
    assert '"wd":false' in r.html
    assert "Chrome/116" not in r.html
    assert "Chrome/116" not in seen.get("user-agent", "")
    # sec-ch-ua, if present, comes from the browser itself and matches its UA
    assert "116" not in seen.get("sec-ch-ua", "")
