"""CLI tests: all verdicts and exit codes, batch worst-wins, attestation."""

import base64
import json

import httpx
import pytest
from conftest import make_signed_record, write_json

from lustro_verify import crypto
from lustro_verify.cli import (
    EXIT_INVALID,
    EXIT_KEY_UNKNOWN,
    EXIT_MALFORMED,
    EXIT_OK,
    main,
)


@pytest.fixture(autouse=True)
def no_env_key(monkeypatch):
    monkeypatch.delenv("LUSTRO_CORE_PUBLIC_KEY_B64", raising=False)
    monkeypatch.setenv("LANG", "en_US.UTF-8")


@pytest.fixture()
def key_file(tmp_path, pub_b64):
    f = tmp_path / "pub.b64"
    f.write_text(pub_b64)
    return str(f)


def run(argv, capsys):
    try:
        code = main(argv)
    except SystemExit as exc:
        code = exc.code
    out = capsys.readouterr()
    return code, out.out, out.err


# ---------- file mode ----------

def test_file_valid_exit0(tmp_path, capsys, keypair, key_file):
    rec = make_signed_record(keypair[0])
    path = write_json(tmp_path / "adv.json", rec)
    code, out, _ = run(["file", path, "--key-file", key_file], capsys)
    assert code == EXIT_OK
    assert "valid" in out


def test_file_invalid_exit1(tmp_path, capsys, keypair, key_file):
    rec = make_signed_record(keypair[0])
    rec["title"] = "tampered after signing"
    path = write_json(tmp_path / "adv.json", rec)
    code, _, _ = run(["file", path, "--key-file", key_file], capsys)
    assert code == EXIT_INVALID


def test_file_key_unknown_exit2(tmp_path, capsys, keypair):
    rec = make_signed_record(keypair[0])
    path = write_json(tmp_path / "adv.json", rec)
    code, out, _ = run(["file", path], capsys)
    assert code == EXIT_KEY_UNKNOWN
    assert "key-unknown" in out


def test_file_empty_exit3(tmp_path, capsys):
    p = tmp_path / "empty.json"
    p.write_text("")
    code, _, _ = run(["file", str(p)], capsys)
    assert code == EXIT_MALFORMED


def test_stdin_malformed_exit3(capsys, monkeypatch):
    monkeypatch.setattr("sys.stdin", type("S", (), {"read": staticmethod(lambda: "{not json")})())
    code, _, _ = run(["file", "-"], capsys)
    assert code == EXIT_MALFORMED


def test_file_missing_signature_exit3(tmp_path, capsys, key_file):
    path = write_json(tmp_path / "nosig.json", {"id": "x", "title": "t"})
    code, _, _ = run(["file", path, "--key-file", key_file], capsys)
    assert code == EXIT_MALFORMED


def test_file_non_string_signature_exit3(tmp_path, capsys, key_file):
    path = write_json(tmp_path / "badtypesig.json", {"id": "x", "signature": 12345})
    code, _, _ = run(["file", path, "--key-file", key_file], capsys)
    assert code == EXIT_MALFORMED


def test_file_bad_b64_signature_exit3(tmp_path, capsys, key_file):
    path = write_json(tmp_path / "badb64.json", {"id": "x", "signature": "!!!"})
    code, _, _ = run(["file", path, "--key-file", key_file], capsys)
    assert code == EXIT_MALFORMED


def test_file_missing_path_exit3(capsys, key_file):
    code, _, _ = run(["file", "/nonexistent/nope.json", "--key-file", key_file], capsys)
    assert code == EXIT_MALFORMED


def test_json_output(tmp_path, capsys, keypair, key_file):
    rec = make_signed_record(keypair[0])
    path = write_json(tmp_path / "adv.json", rec)
    code, out, _ = run(["file", path, "--key-file", key_file, "--json"], capsys)
    assert code == EXIT_OK
    doc = json.loads(out)
    assert doc["verdict"] == "valid"
    assert "key_fingerprint" in doc


# ---------- batch mode ----------

def _feed(keypair, n_valid=2, n_invalid=0, n_malformed=0, n_nosig=0):
    items = [make_signed_record(keypair[0], {"id": f"ok-{i}"}) for i in range(n_valid)]
    for i in range(n_invalid):
        r = make_signed_record(keypair[0], {"id": f"bad-{i}"})
        r["title"] = "tampered"
        items.append(r)
    for i in range(n_malformed):
        items.append({"id": f"mal-{i}", "signature": "@@@not-b64@@@"})
    for i in range(n_nosig):
        items.append({"id": f"nosig-{i}", "title": "t"})
    return {"items": items, "generated_at": "2026-07-27T00:00:00Z"}


def test_batch_all_valid_exit0(tmp_path, capsys, keypair, key_file):
    path = write_json(tmp_path / "feed.json", _feed(keypair))
    code, out, _ = run(["batch", path, "--key-file", key_file, "--json"], capsys)
    assert code == EXIT_OK
    report = json.loads(out)
    assert report["counts"]["valid"] == 2
    assert report["attestation"]["mode"] == "hashed"
    assert len(report["attestation"]["payload_sha256"]) == 64
    assert report["tool_version"]


def test_batch_any_invalid_exit1(tmp_path, capsys, keypair, key_file):
    path = write_json(tmp_path / "feed.json", _feed(keypair, n_invalid=1))
    code, _, _ = run(["batch", path, "--key-file", key_file], capsys)
    assert code == EXIT_INVALID


def test_batch_malformed_worst_wins_exit3(tmp_path, capsys, keypair, key_file):
    path = write_json(tmp_path / "feed.json", _feed(keypair, n_invalid=1, n_malformed=1))
    code, _, _ = run(["batch", path, "--key-file", key_file], capsys)
    assert code == EXIT_MALFORMED


def test_batch_key_unknown_exit2(tmp_path, capsys, keypair):
    path = write_json(tmp_path / "feed.json", _feed(keypair))
    code, _, _ = run(["batch", path], capsys)
    assert code == EXIT_KEY_UNKNOWN


def test_batch_invalid_beats_key_unknown(tmp_path, capsys, keypair):
    # key unavailable AND an item with malformed signature → malformed wins
    path = write_json(tmp_path / "feed.json", _feed(keypair, n_malformed=1))
    code, _, _ = run(["batch", path], capsys)
    assert code == EXIT_MALFORMED


def test_batch_empty_items_exit3(tmp_path, capsys, key_file):
    path = write_json(tmp_path / "feed.json", {"items": []})
    code, _, _ = run(["batch", path, "--key-file", key_file], capsys)
    assert code == EXIT_MALFORMED


def test_batch_mixed_feed_export(tmp_path, capsys, keypair, key_file):
    """Mixed feed: valid, invalid, correction-shaped, extra unknown fields."""
    feed = _feed(keypair, n_valid=1, n_invalid=1)
    from lustro_verify import canon as _canon

    corr = {
        "id": "corr-1",
        "match_id": "ok-0",
        "state": "confirmed",
        "published_at": "2026-07-27T11:00:00Z",
        "unknown_extra_field": {"nested": True},
    }
    corr["signature"] = crypto.sign(
        _canon.canonicalize(corr, "json-minus-signature"), keypair[0]
    )
    feed["items"].append(corr)
    path = write_json(tmp_path / "feed.json", feed)
    code, out, _ = run(["batch", path, "--key-file", key_file, "--json"], capsys)
    assert code == EXIT_INVALID
    report = json.loads(out)
    assert report["counts"]["valid"] == 2
    assert report["counts"]["invalid"] == 1
    types = {r["type"] for r in report["results"]}
    assert "correction" in types


def test_batch_signed_attestation(tmp_path, capsys, keypair, key_file):
    priv, pub = crypto.generate_local_keypair()
    sf = tmp_path / "sign.b64"
    sf.write_text(base64.b64encode(priv).decode())
    path = write_json(tmp_path / "feed.json", _feed(keypair))
    code, out, _ = run(
        ["batch", path, "--key-file", key_file, "--signing-key-file", str(sf), "--json"], capsys
    )
    assert code == EXIT_OK
    report = json.loads(out)
    att = report["attestation"]
    assert att["mode"] == "signed"
    body = dict(report)
    del body["attestation"]
    payload = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    assert crypto.verify(payload, att["signature"], pub) is True


# ---------- fetch mode (mocked) ----------

def _mock_fetcher(monkeypatch, record):
    from lustro_verify.fetch import LustroFetcher, TokenBucket

    def handler(request):
        return httpx.Response(200, json=record)

    transport = httpx.MockTransport(handler)
    client = httpx.Client(base_url="https://test.invalid", transport=transport)

    def factory(self=None, base_url=None):
        f = LustroFetcher(base_url=base_url or "https://test.invalid", client=client)
        f._bucket = TokenBucket(rate_per_minute=1e9)
        return f

    monkeypatch.setattr("lustro_verify.cli.LustroFetcher", lambda base_url=None: factory(base_url=base_url))


def test_advisory_fetch_valid(monkeypatch, capsys, keypair, key_file):
    _mock_fetcher(monkeypatch, make_signed_record(keypair[0]))
    code, out, _ = run(["advisory", "adv-1", "--key-file", key_file], capsys)
    assert code == EXIT_OK


def test_correction_fetch_invalid(monkeypatch, capsys, keypair, key_file):
    rec = make_signed_record(keypair[0])
    rec["body"] = "edited"
    _mock_fetcher(monkeypatch, rec)
    code, _, _ = run(["correction", "corr-1", "--key-file", key_file], capsys)
    assert code == EXIT_INVALID


def test_env_key_used(tmp_path, capsys, keypair, pub_b64, monkeypatch):
    monkeypatch.setenv("LUSTRO_CORE_PUBLIC_KEY_B64", pub_b64)
    path = write_json(tmp_path / "adv.json", make_signed_record(keypair[0]))
    code, _, _ = run(["file", path], capsys)
    assert code == EXIT_OK


def test_polish_output(tmp_path, capsys, keypair, key_file, monkeypatch):
    monkeypatch.setenv("LANG", "pl_PL.UTF-8")
    path = write_json(tmp_path / "adv.json", make_signed_record(keypair[0]))
    code, out, _ = run(["file", path, "--key-file", key_file], capsys)
    assert code == EXIT_OK
    assert "werdykt" in out
