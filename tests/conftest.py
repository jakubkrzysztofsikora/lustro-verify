import base64
import json

import pytest

from lustro_verify import canon, crypto


@pytest.fixture()
def keypair():
    priv_raw, pub_raw = crypto.generate_local_keypair()
    return priv_raw, pub_raw


@pytest.fixture()
def pub_b64(keypair):
    return base64.b64encode(keypair[1]).decode()


def make_signed_record(priv_raw: bytes, extra: dict | None = None) -> dict:
    """Build a signed advisory-shaped record using the default canon scheme."""
    record = {
        "id": "adv-test-1",
        "title": "Test advisory — żółć gęślą jaźń",
        "body": "Coordinated narrative about a fictional event.",
        "confidence": 0.87,
        "published_at": "2026-07-27T10:00:00Z",
    }
    if extra:
        record.update(extra)
    payload = canon.canonicalize(record, "json-minus-signature")
    record["signature"] = crypto.sign(payload, priv_raw)
    return record


@pytest.fixture()
def signed_record(keypair):
    return make_signed_record(keypair[0])


def write_json(path, doc) -> str:
    path.write_text(json.dumps(doc, ensure_ascii=False), encoding="utf-8")
    return str(path)
