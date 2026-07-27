"""Polite LUSTRO API fetcher.

HARD-RULES compliance:
  - token-bucket rate limiter capped at 25 req/min (API limit is 30/min per IP)
  - honors 429 + Retry-After, exponential backoff with jitter
  - defensive parsing for v0.1.0 (tolerate extra/missing fields, 422/429)
"""

from __future__ import annotations

import random
import time
from dataclasses import dataclass, field

import httpx

DEFAULT_BASE_URL = "https://projektlustro.eu"
RATE_PER_MINUTE = 25.0
MAX_RETRIES = 5
USER_AGENT = "lustro-verify/0.1.0 (+https://github.com/projektlustro/lustro-verify)"


class FetchError(Exception):
    """Raised on unrecoverable fetch failures (non-retriable status, network)."""


class TokenBucket:
    """Simple token bucket: capacity RATE_PER_MINUTE, refills continuously."""

    def __init__(self, rate_per_minute: float = RATE_PER_MINUTE):
        self.capacity = rate_per_minute
        self.tokens = rate_per_minute
        self.refill_per_sec = rate_per_minute / 60.0
        self.last = time.monotonic()

    def acquire(self) -> None:
        while True:
            now = time.monotonic()
            self.tokens = min(
                self.capacity, self.tokens + (now - self.last) * self.refill_per_sec
            )
            self.last = now
            if self.tokens >= 1.0:
                self.tokens -= 1.0
                return
            time.sleep((1.0 - self.tokens) / self.refill_per_sec)


@dataclass
class LustroFetcher:
    base_url: str = DEFAULT_BASE_URL
    client: httpx.Client | None = None
    _bucket: TokenBucket = field(default_factory=TokenBucket)
    _own_client: bool = field(default=False, init=False)

    def _get_client(self) -> httpx.Client:
        if self.client is None:
            self.client = httpx.Client(
                base_url=self.base_url,
                timeout=20.0,
                headers={"User-Agent": USER_AGENT},
                follow_redirects=True,
            )
            self._own_client = True
        return self.client

    def close(self) -> None:
        if self._own_client and self.client is not None:
            self.client.close()
            self.client = None

    def _request(self, path: str, params: dict | None = None) -> dict:
        client = self._get_client()
        for attempt in range(MAX_RETRIES):
            self._bucket.acquire()
            try:
                resp = client.get(path, params=params)
            except httpx.HTTPError as exc:
                if attempt == MAX_RETRIES - 1:
                    raise FetchError(f"network error fetching {path}: {exc}") from exc
                time.sleep(min(2**attempt + random.uniform(0, 0.5), 30.0))
                continue
            if resp.status_code == 429:
                retry_after = resp.headers.get("Retry-After")
                try:
                    delay = float(retry_after) if retry_after else 2.0**attempt
                except ValueError:
                    delay = 2.0**attempt
                time.sleep(min(delay + random.uniform(0, 0.5), 60.0))
                continue
            if resp.status_code == 404:
                raise FetchError(f"not found: {path}")
            if resp.status_code == 422:
                raise FetchError(f"unprocessable request {path}: {resp.text[:200]}")
            if resp.status_code >= 400:
                if attempt == MAX_RETRIES - 1:
                    raise FetchError(f"HTTP {resp.status_code} for {path}")
                time.sleep(min(2**attempt + random.uniform(0, 0.5), 30.0))
                continue
            try:
                doc = resp.json()
            except ValueError as exc:
                raise FetchError(f"non-JSON response from {path}") from exc
            if not isinstance(doc, dict):
                raise FetchError(f"unexpected JSON shape from {path}")
            return doc
        raise FetchError(f"exhausted retries for {path}")

    def get_advisory(self, advisory_id: str) -> dict:
        return self._request(f"/v1/advisory/{advisory_id}")

    def get_correction(self, correction_id: str) -> dict:
        return self._request(f"/v1/corrections/{correction_id}")

    def get_feed_page(self, limit: int = 50, cursor: str | None = None) -> dict:
        params: dict = {"limit": limit}
        if cursor:
            params["cursor"] = cursor
        return self._request("/v1/feed", params=params)

    def iter_feed(self, limit: int = 50, max_pages: int | None = None):
        """Yield feed items via cursor pagination until exhausted."""
        cursor: str | None = None
        pages = 0
        while True:
            page = self.get_feed_page(limit=limit, cursor=cursor)
            items = page.get("items")
            if isinstance(items, list):
                for item in items:
                    if isinstance(item, dict):
                        yield item
            nxt = page.get("next")
            pages += 1
            if not isinstance(nxt, str) or not nxt or (max_pages and pages >= max_pages):
                return
            cursor = nxt

    def health(self) -> dict:
        return self._request("/api/health")

    def classifier_fallback(self) -> bool:
        """True when /api/health reports classifier_loaded=false (keyword
        fallback scoring in effect)."""
        try:
            h = self.health()
        except FetchError:
            return False
        clf = h.get("classifier")
        if isinstance(clf, dict):
            return clf.get("classifier_loaded") is False
        return False
