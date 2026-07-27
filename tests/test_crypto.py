import base64

import pytest

from lustro_verify import crypto


class TestDecodeSignature:
    def test_non_string_signature(self):
        with pytest.raises(crypto.MalformedSignatureError):
            crypto.decode_signature_b64(123)
        with pytest.raises(crypto.MalformedSignatureError):
            crypto.decode_signature_b64(None)
        with pytest.raises(crypto.MalformedSignatureError):
            crypto.decode_signature_b64({"sig": "x"})

    def test_bad_base64(self):
        with pytest.raises(crypto.MalformedSignatureError):
            crypto.decode_signature_b64("!!!not-base64!!!")

    def test_bad_padding_tolerated(self):
        raw = b"s" * 64
        b64 = base64.b64encode(raw).decode().rstrip("=")
        assert crypto.decode_signature_b64(b64) == raw

    def test_wrong_length(self):
        with pytest.raises(crypto.MalformedSignatureError):
            crypto.decode_signature_b64(base64.b64encode(b"too short").decode())

    def test_valid(self):
        raw = bytes(range(64))
        assert crypto.decode_signature_b64(base64.b64encode(raw).decode()) == raw


class TestDecodeKey:
    def test_wrong_length(self):
        with pytest.raises(crypto.KeyUnavailableError):
            crypto.decode_key_b64(base64.b64encode(b"short").decode())

    def test_bad_base64(self):
        with pytest.raises(crypto.KeyUnavailableError):
            crypto.decode_key_b64("###")

    def test_padding_tolerated(self):
        raw = b"k" * 32
        assert crypto.decode_key_b64(base64.b64encode(raw).decode().rstrip("=")) == raw


class TestVerify:
    def test_roundtrip(self, keypair):
        priv, pub = keypair
        payload = b'{"a":1}'
        sig = crypto.sign(payload, priv)
        assert crypto.verify(payload, sig, pub) is True

    def test_wrong_key(self, keypair):
        priv, _pub = keypair
        _priv2, pub2 = crypto.generate_local_keypair()
        sig = crypto.sign(b"payload", priv)
        assert crypto.verify(b"payload", sig, pub2) is False

    def test_tampered_payload(self, keypair):
        priv, pub = keypair
        sig = crypto.sign(b'{"a":1}', priv)
        assert crypto.verify(b'{"a":2}', sig, pub) is False

    def test_malformed_signature_raises(self, keypair):
        assert_raises = pytest.raises(crypto.MalformedSignatureError)
        with assert_raises:
            crypto.verify(b"p", 42, keypair[1])

    def test_fingerprint_format(self, keypair):
        fp = crypto.fingerprint(keypair[1])
        assert len(fp.split(":")) == 32


class TestResolveKey:
    def test_key_file(self, tmp_path, pub_b64):
        f = tmp_path / "key.b64"
        f.write_text(pub_b64)
        kr = crypto.resolve_key(key_file=str(f))
        assert len(kr.pubkey) == 32
        assert kr.source.startswith("key-file:")

    def test_key_file_missing(self, tmp_path):
        with pytest.raises(crypto.KeyUnavailableError):
            crypto.resolve_key(key_file=str(tmp_path / "nope"))

    def test_key_b64_priority_over_env(self, keypair, pub_b64, monkeypatch):
        _p2, pub2 = crypto.generate_local_keypair()
        monkeypatch.setenv("LUSTRO_CORE_PUBLIC_KEY_B64", base64.b64encode(pub2).decode())
        kr = crypto.resolve_key(key_b64=pub_b64)
        assert kr.pubkey == keypair[1]

    def test_env_fallback(self, keypair, pub_b64, monkeypatch):
        monkeypatch.setenv("LUSTRO_CORE_PUBLIC_KEY_B64", pub_b64)
        kr = crypto.resolve_key()
        assert kr.pubkey == keypair[1]

    def test_no_key(self, monkeypatch):
        monkeypatch.delenv("LUSTRO_CORE_PUBLIC_KEY_B64", raising=False)
        with pytest.raises(crypto.KeyUnavailableError):
            crypto.resolve_key()
