"""The stdio MCP server in crawl4ai.fortress_mcp: input validation, paging,
egress blocking and the vendored egress modules."""

import asyncio
import pathlib
import re

import pytest

pytest.importorskip("mcp")

from crawl4ai.fortress import find_fortress_path  # noqa: E402
from crawl4ai.fortress_mcp import server as S  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parents[2]


def _call(**kwargs):
    return asyncio.run(S.read_url(**kwargs))


# ── vendored egress code must match deploy/docker ──────────────────────


@pytest.mark.parametrize("name", ["egress_broker", "egress_proxy"])
def test_vendored_egress_matches_docker_copy(name):
    original = (ROOT / "deploy" / "docker" / f"{name}.py").read_text()
    vendored = (ROOT / "crawl4ai" / "fortress_mcp" / f"{name}.py").read_text()
    vendored = re.sub(r"\A(#.*\n)+", "", vendored).replace("from .egress_broker import", "from egress_broker import")
    assert vendored == original, f"re-copy deploy/docker/{name}.py into crawl4ai/fortress_mcp/"


# ── input validation (no browser needed) ───────────────────────────────


@pytest.mark.parametrize(
    "url, message",
    [
        ("file:///etc/passwd", "only http and https"),
        ("raw:<p>x</p>", "only http and https"),
        ("javascript:alert(1)", "only http and https"),
        ("https://user:pw@example.com/", "credentials"),
        ("http://localhost:8080/", "URL blocked"),
        ("http://127.0.0.1/", "URL blocked"),
        ("http://[::1]/", "URL blocked"),
        ("http://169.254.169.254/latest/meta-data/", "URL blocked"),
        ("http://10.0.0.1/", "URL blocked"),
        ("http://192.168.1.1/", "URL blocked"),
        ("http://[::ffff:127.0.0.1]/", "URL blocked"),
    ],
)
def test_rejects_unsafe_urls(url, message, monkeypatch):
    async def must_not_fetch(*a, **k):
        raise AssertionError("browser reached")

    monkeypatch.setattr(S.reader, "fetch", must_not_fetch)
    assert message in _call(url=url, mode="full")


def test_rejects_unknown_mode():
    assert "mode must be" in _call(url="https://example.com", mode="js")


# ── paging and output shape ────────────────────────────────────────────


def test_slice_splits_on_paragraphs(monkeypatch):
    monkeypatch.setattr(S, "PAGE_CHARS", 100)
    text = "\n\n".join(f"paragraph {i} " + "x" * 30 for i in range(12))
    pages = []
    first, total = S._slice(text, 1, 100)
    for p in range(1, total + 1):
        chunk, _ = S._slice(text, p, 100)
        assert len(chunk) <= 100
        pages.append(chunk)
    assert total > 1
    assert "".join(pages) == text
    assert first == pages[0]


def test_slice_never_cuts_words_when_lines_exist(monkeypatch):
    monkeypatch.setattr(S, "PAGE_CHARS", 100)
    text = "\n".join(f"line {i} with some words in it" for i in range(20))
    total = S._slice(text, 1)[1]
    chunks = [S._slice(text, p)[0] for p in range(1, total + 1)]
    assert "".join(chunks) == text
    assert all(c.rstrip().endswith("it") for c in chunks)


def test_output_marks_content_untrusted_and_pages(monkeypatch):
    monkeypatch.setattr(S, "PAGE_CHARS", 250)  # read_url never cuts below 200
    page = {"url": "https://example.com/", "status": 200, "title": "T", "text": "a" * 240 + "\n\n" + "b" * 240}

    async def fake_fetch(url, mode):
        return page

    monkeypatch.setattr(S.reader, "fetch", fake_fetch)
    monkeypatch.setattr(S, "resolve_and_pin", lambda url: None)

    out = _call(url="https://example.com/", mode="article", page=2)
    assert "Page 2/2" in out
    assert out.rstrip().endswith("</untrusted-web-content>")
    assert "b" * 240 in out and "a" * 240 not in out
    assert "page 3 does not exist" in _call(url="https://example.com/", mode="article", page=3)


def test_dead_browser_reported_as_failed_result_relaunches(monkeypatch):
    """arun() swallows a dead browser into result.success=False; the reader must
    still relaunch it once instead of failing every later call."""
    from types import SimpleNamespace

    dead = SimpleNamespace(success=False, status_code=None, redirected_url=None,
                           error_message="Unexpected error in _crawl_web at line 636 in wrap_api_call (x)")
    md = SimpleNamespace(raw_markdown="hello " * 100, fit_markdown="hello " * 100)
    good = SimpleNamespace(success=True, status_code=200, redirected_url="https://example.com/", markdown=md,
                           metadata={"title": "T"}, url="https://example.com/", error_message=None)
    crawlers, resets = [dead, good], []

    class FakeCrawler:
        def __init__(self, result):
            self.result = result

        async def arun(self, url, config=None):
            return self.result

    r = S.Reader()

    async def ensure():
        return FakeCrawler(crawlers[len(resets)])

    async def reset():
        resets.append(1)

    monkeypatch.setattr(r, "_ensure_started", ensure)
    monkeypatch.setattr(r, "_reset", reset)
    out = asyncio.run(r.fetch("https://example.com/", "article"))
    assert resets == [1]
    assert "hello" in out["text"]


# ── end to end through Fortress ────────────────────────────────────────


def _fortress_available():
    try:
        find_fortress_path()
        return True
    except FileNotFoundError:
        return False


@pytest.mark.skipif(not _fortress_available(), reason="Fortress not installed")
def test_redirect_to_loopback_never_reaches_target():
    """A public page redirecting to 127.0.0.1 is stopped by the pinning proxy:
    the local server sees no request at all."""
    import http.server
    import threading

    hits = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            hits.append(self.path)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"SECRET-INTERNAL-MARKER")

        def log_message(self, *a):
            pass

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    target = f"http://127.0.0.1:{srv.server_address[1]}/"

    async def run():
        try:
            return await S.read_url(f"https://httpbin.org/redirect-to?url={target}", mode="full")
        finally:
            await S.reader.close()
            S.reader._crawler = None
            S.reader._proxy = None

    try:
        out = asyncio.run(run())
    finally:
        srv.shutdown()
    assert hits == []
    assert "SECRET-INTERNAL-MARKER" not in out
    assert "URL blocked" in out
