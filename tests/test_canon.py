import json

import pytest

from lustro_verify import canon


def test_canonical_form():
    rec = {"b": 1, "a": "żółć", "signature": "xyz"}
    out = canon.canonicalize(rec)
    assert out == json.dumps(
        {"a": "żółć", "b": 1}, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    assert "signature" not in out.decode()


def test_unicode_not_escaped():
    out = canon.canonicalize({"x": "ąćę"})
    assert "ąćę".encode() in out


def test_signature_removed_recursively_not_required():
    rec = {"nested": {"signature": "keep"}, "signature": "drop"}
    out = canon.canonicalize(rec)
    doc = json.loads(out)
    assert "signature" not in doc
    assert doc["nested"]["signature"] == "keep"


def test_null_signature_variant():
    out = canon.canonicalize({"a": 1, "signature": "s"}, "json-with-null-signature")
    assert json.loads(out)["signature"] is None


def test_unknown_scheme():
    with pytest.raises(canon.CanonError):
        canon.canonicalize({"a": 1}, "nonsense")


def test_non_dict():
    with pytest.raises(canon.CanonError):
        canon.canonicalize([1, 2])


def test_detect_record_type():
    assert canon.detect_record_type({"match_id": "x", "state": "confirmed"}) == "correction"
    assert canon.detect_record_type({"body": "b", "evidence": []}) == "advisory"
    assert canon.detect_record_type({"title": "t", "signature": "s"}) == "feed-item"
    assert canon.detect_record_type({"random": True}) == "unknown"
    assert canon.detect_record_type([1]) == "unknown"


def test_iter_feed_items():
    assert canon.iter_feed_items({"items": [{"a": 1}, "junk", {"b": 2}]}) == [{"a": 1}, {"b": 2}]
    assert canon.iter_feed_items([{"a": 1}]) == [{"a": 1}]
    assert canon.iter_feed_items({"signature": "s", "id": "1"}) == [{"signature": "s", "id": "1"}]
    assert canon.iter_feed_items({"no_items": True}) == []
