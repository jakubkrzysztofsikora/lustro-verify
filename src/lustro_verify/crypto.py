"""Ed25519 signature verification and public-key acquisition for lustro-verify.

Key format: raw 32-byte Ed25519 public key, base64-encoded.
Signature format: base64-encoded 64 raw bytes.

Public-key sources (priority order):
  1. --key-file (local file with base64 key)
  2. --key-b64 / env LUSTRO_CORE_PUBLIC_KEY_B64
  3. --key-url with TOFU pinning (SHA-256 fingerprint stored in
     ~/.config/lustro-verify/known_keys)

Recon (2026-07-27) found that ghcr.io/projektlustro/node-agent ships with an
EMPTY LUSTRO_NODE_AGENT_PINNED_KEY_B64 (fail-closed); only a dev key exists,
gated by LUSTRO_NODE_AGENT_DEV=1, which does not verify live advisories. The
production key is therefore NOT programmatically obtainable and MUST be
injected by the operator. If no key is obtainable, verification reports the
`key-unknown` verdict (exit 2) rather than guessing.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        NoEncryption,
        PrivateFormat,
        PublicFormat,
    )

    _HAS_CRYPTO = True
except ImportError:  # pragma: no cover - cryptography is a declared dep
    _HAS_CRYPTO = False


class KeyUnavailableError(Exception):
    """Raised when no usable verification key could be obtained."""


class MalformedSignatureError(Exception):
    """Raised when the signature field cannot be decoded to 64 raw bytes."""


KNOWN_KEYS_DIR = Path.home() / ".config" / "lustro-verify"
KNOWN_KEYS_PATH = KNOWN_KEYS_DIR / "known_keys"


def decode_key_b64(key_b64: str) -> bytes:
    """Decode a base64 public key to raw 32 bytes. Tolerates whitespace and
    missing padding."""
    cleaned = "".join(str(key_b64).split())
    pad = (-len(cleaned)) % 4
    try:
        raw = base64.b64decode(cleaned + "=" * pad, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise KeyUnavailableError(f"public key is not valid base64: {exc}") from exc
    if len(raw) != 32:
        raise KeyUnavailableError(
            f"public key must decode to 32 raw bytes, got {len(raw)}"
        )
    return raw


def decode_signature_b64(signature: object) -> bytes:
    """Decode the base64 `signature` field to raw 64 bytes.

    Raises MalformedSignatureError for non-string input or wrong length.
    Tolerates missing base64 padding.
    """
    if not isinstance(signature, str):
        raise MalformedSignatureError(
            f"signature field must be a base64 string, got {type(signature).__name__}"
        )
    cleaned = "".join(signature.split())
    pad = (-len(cleaned)) % 4
    try:
        raw = base64.b64decode(cleaned + "=" * pad, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise MalformedSignatureError(f"signature is not valid base64: {exc}") from exc
    if len(raw) != 64:
        raise MalformedSignatureError(
            f"signature must decode to 64 raw bytes, got {len(raw)}"
        )
    return raw


def fingerprint(pubkey_bytes: bytes) -> str:
    """SHA-256 fingerprint of the raw public key, colon-separated hex."""
    digest = hashlib.sha256(pubkey_bytes).hexdigest()
    return ":".join(digest[i : i + 2] for i in range(0, 64, 2))


def verify(payload_bytes: bytes, signature_b64: object, pubkey_bytes: bytes) -> bool:
    """Verify an Ed25519 signature over payload_bytes.

    Returns True/False. Raises MalformedSignatureError on undecodable
    signatures and KeyUnavailableError on unusable keys.
    """
    if not _HAS_CRYPTO:  # pragma: no cover
        raise KeyUnavailableError("cryptography package not available")
    if len(pubkey_bytes) != 32:
        raise KeyUnavailableError("public key must be 32 raw bytes")
    sig = decode_signature_b64(signature_b64)
    key = Ed25519PublicKey.from_public_bytes(pubkey_bytes)
    try:
        key.verify(sig, payload_bytes)
    except InvalidSignature:
        return False
    return True


def generate_local_keypair() -> tuple[bytes, bytes]:
    """Generate an Ed25519 keypair (private_raw, public_raw). Used for batch
    attestation signing and tests."""
    if not _HAS_CRYPTO:  # pragma: no cover
        raise KeyUnavailableError("cryptography package not available")
    priv = Ed25519PrivateKey.generate()
    priv_raw = priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    pub_raw = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return priv_raw, pub_raw


def sign(payload_bytes: bytes, privkey_bytes: bytes) -> str:
    """Sign payload_bytes with a raw 32-byte Ed25519 private key; return b64."""
    if not _HAS_CRYPTO:  # pragma: no cover
        raise KeyUnavailableError("cryptography package not available")
    key = Ed25519PrivateKey.from_private_bytes(privkey_bytes)
    return base64.b64encode(key.sign(payload_bytes)).decode("ascii")


@dataclass
class KeyResult:
    pubkey: bytes
    source: str  # e.g. "key-file:/path", "key-url:https://...", "env:LUSTRO_CORE_PUBLIC_KEY_B64"


def _load_tofu_store() -> dict:
    if KNOWN_KEYS_PATH.is_file():
        try:
            return json.loads(KNOWN_KEYS_PATH.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return {}
    return {}


def _save_tofu_store(store: dict) -> None:
    KNOWN_KEYS_DIR.mkdir(parents=True, exist_ok=True)
    KNOWN_KEYS_PATH.write_text(json.dumps(store, indent=2, sort_keys=True), encoding="utf-8")
    try:
        os.chmod(KNOWN_KEYS_PATH, 0o600)
    except OSError:
        pass


def fetch_key_url(url: str, *, trust: bool = False, verbose: bool = False) -> KeyResult:
    """Fetch a base64 key from a URL with TOFU pinning.

    On first use the SHA-256 fingerprint is displayed and pinned in
    ~/.config/lustro-verify/known_keys. On subsequent uses a fingerprint
    mismatch is fatal. `trust=True` (/--trust-new-key) overrides pinning.
    """
    import httpx

    resp = httpx.get(url, timeout=15.0, follow_redirects=True)
    resp.raise_for_status()
    body = resp.text.strip()
    # Accept either raw base64 text or JSON {"key_b64": "..."}
    try:
        parsed = json.loads(body)
        if isinstance(parsed, dict) and "key_b64" in parsed:
            body = str(parsed["key_b64"])
    except json.JSONDecodeError:
        pass
    pubkey = decode_key_b64(body)
    fp = fingerprint(pubkey)

    store = _load_tofu_store()
    pinned = store.get(url)
    if pinned and pinned != fp and not trust:
        raise KeyUnavailableError(
            f"TOFU key mismatch for {url}\n"
            f"  pinned:   {pinned}\n"
            f"  received: {fp}\n"
            "Refusing to use the new key. If this rotation is expected, re-run with --trust-new-key."
        )
    if not pinned or trust:
        store[url] = fp
        _save_tofu_store(store)
        if verbose:
            print(f"[tofu] pinned new key for {url}\n[tofu] sha256 fingerprint: {fp}")
    elif verbose:
        print(f"[tofu] key for {url} matches pinned fingerprint {fp}")
    return KeyResult(pubkey=pubkey, source=f"key-url:{url}")


def resolve_key(
    *,
    key_file: str | None = None,
    key_b64: str | None = None,
    key_url: str | None = None,
    trust: bool = False,
    verbose: bool = False,
) -> KeyResult:
    """Resolve a verification key from the configured sources, in priority
    order: --key-file > --key-b64 / env > --key-url. Raises KeyUnavailableError
    if nothing works."""
    if key_file:
        path = Path(key_file)
        try:
            raw_b64 = path.read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise KeyUnavailableError(f"cannot read key file {key_file}: {exc}") from exc
        return KeyResult(pubkey=decode_key_b64(raw_b64), source=f"key-file:{path}")

    candidate = key_b64 or os.environ.get("LUSTRO_CORE_PUBLIC_KEY_B64")
    if candidate:
        source = "key-b64" if key_b64 else "env:LUSTRO_CORE_PUBLIC_KEY_B64"
        return KeyResult(pubkey=decode_key_b64(candidate), source=source)

    if key_url:
        return fetch_key_url(key_url, trust=trust, verbose=verbose)

    raise KeyUnavailableError(
        "no verification key available. Provide one of: --key-file, --key-b64, "
        "env LUSTRO_CORE_PUBLIC_KEY_B64, or --key-url (TOFU-pinned). "
        "The production key is not programmatically obtainable (node-agent image "
        "ships fail-closed with an empty pinned key)."
    )
