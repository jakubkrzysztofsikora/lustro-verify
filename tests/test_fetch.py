"""Fetch tests with fully mocked httpx transport — no live network."""

import httpx
import pytest

from lustro_verify.fetch import FetchError, LustroFetcher, TokenBucket


def make_fetcher(handler):
    transport = httpx.MockTransport(handler)
    client = httpx.Client(base_url="https://test.invalid", transport=transport)
    return LustroFetcher(base_url="https://test.invalid", client=client)


def fast(fetcher):
    """Disable politeness sleeps for unit tests."""
    fetcher._bucket = TokenBucket(rate_per_minute=1e9)
    return fetcher


def test_get_advisory():
    def handler(request):
        assert request.url.path == "/v1/advisory/abc"
        return httpx.Response(200, json={"id": "abc", "signature": "s"})

    f = fast(make_fetcher(handler))
    assert f.get_advisory("abc")["id"] == "abc"


def test_404():
    f = fast(make_fetcher(lambda r: httpx.Response(404, json={"detail": "nope"})))
    with pytest.raises(FetchError, match="not found"):
        f.get_advisory("missing")


def test_422():
    f = fast(make_fetcher(lambda r: httpx.Response(422, json={"detail": []})))
    with pytest.raises(FetchError, match="unprocessable"):
        f.get_feed_page(limit="bogus")


def test_429_retry_after(monkeypatch):
    calls = {"n": 0}

    def handler(request):
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(429, headers={"Retry-After": "0"}, json={"detail": "slow down"})
        return httpx.Response(200, json={"ok": True})

    monkeypatch.setattr("time.sleep", lambda s: None)
    f = fast(make_fetcher(handler))
    assert f.health() == {"ok": True}
    assert calls["n"] == 2


def test_429_exhausted(monkeypatch):
    monkeypatch.setattr("time.sleep", lambda s: None)
    f = fast(make_fetcher(lambda r: httpx.Response(429, json={})))
    with pytest.raises(FetchError):
        f.health()


def test_pagination():
    pages = [
        {"items": [{"id": "1"}, {"id": "2"}], "next": "cursor-2"},
        {"items": [{"id": "3"}], "next": None},
    ]
    state = {"i": 0}

    def handler(request):
        doc = pages[state["i"]]
        state["i"] += 1
        return httpx.Response(200, json=doc)

    f = fast(make_fetcher(handler))
    ids = [it["id"] for it in f.iter_feed()]
    assert ids == ["1", "2", "3"]


def test_pagination_max_pages():
    def handler(request):
        return httpx.Response(200, json={"items": [{"id": "x"}], "next": "more"})

    f = fast(make_fetcher(handler))
    assert len(list(f.iter_feed(max_pages=2))) == 2


def test_classifier_fallback():
    f = fast(make_fetcher(lambda r: httpx.Response(200, json={"classifier": {"classifier_loaded": False}})))
    assert f.classifier_fallback() is True
    f2 = fast(make_fetcher(lambda r: httpx.Response(200, json={"classifier": {"classifier_loaded": True}})))
    assert f2.classifier_fallback() is False
    f3 = fast(make_fetcher(lambda r: httpx.Response(500, json={})))
    assert f3.classifier_fallback() is False


def test_defensive_non_json():
    f = fast(make_fetcher(lambda r: httpx.Response(200, content=b"<html>oops</html>")))
    with pytest.raises(FetchError, match="non-JSON"):
        f.health()
