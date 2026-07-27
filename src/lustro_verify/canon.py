"""Canonical payload reconstruction for LUSTRO signature verification.

Default convention (candidate `json-minus-signature`):
    JSON of the record minus the `signature` field, keys sorted,
    separators=(',', ':'), ensure_ascii=False, UTF-8 encoding.

The exact production canon convention has NOT been empirically confirmed (no
production key is available to test against). Variants are provided and the
scheme used is always reported; when verification fails the verdict stays
honest (`invalid` vs `unverifiable-scheme` distinction is reported in verbose
output rather than guessing).
"""

from __future__ import annotations

import json

CANON_SCHEMES = ("json-minus-signature", "json-with-null-signature")


class CanonError(Exception):
    """Raised when a record cannot be canonicalized (e.g. not a JSON object)."""


def canonicalize(record: dict, scheme: str = "json-minus-signature") -> bytes:
    """Reconstruct the canonical signed payload for a record.

    - json-minus-signature: record minus `signature`, sort_keys, compact
      separators, ensure_ascii=False, UTF-8.
    - json-with-null-signature: same, but `signature` replaced with null.
    """
    if not isinstance(record, dict):
        raise CanonError(
            f"record must be a JSON object, got {type(record).__name__}"
        )
    if scheme == "json-minus-signature":
        body = {k: v for k, v in record.items() if k != "signature"}
    elif scheme == "json-with-null-signature":
        body = dict(record)
        body["signature"] = None
    else:
        raise CanonError(f"unknown canon scheme: {scheme}")
    return json.dumps(
        body, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def detect_record_type(record: dict) -> str:
    """Heuristically classify a JSON object as advisory / correction / feed-item
    / unknown. Defensive: tolerate missing or extra fields."""
    if not isinstance(record, dict):
        return "unknown"
    if "match_id" in record or "state" in record:
        return "correction"
    if "body" in record or "evidence" in record:
        return "advisory"
    if "title" in record and "signature" in record:
        return "feed-item"
    return "unknown"


def iter_feed_items(doc: object) -> list[dict]:
    """Normalize a feed export into a list of item dicts.

    Accepts: a full feed response {items: [...]}, a bare list of items, or a
    single item dict."""
    if isinstance(doc, dict) and isinstance(doc.get("items"), list):
        return [it for it in doc["items"] if isinstance(it, dict)]
    if isinstance(doc, list):
        return [it for it in doc if isinstance(it, dict)]
    if isinstance(doc, dict) and "signature" in doc:
        return [doc]
    return []
