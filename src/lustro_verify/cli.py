"""lustro-verify CLI.

Verdicts: valid, invalid, key-unknown, malformed.
Exit codes: 0 valid, 1 invalid, 2 key unavailable, 3 malformed input.
Batch exit: 0 all valid; 1 any invalid; 3 any malformed; 2 if key unavailable
and nothing worse (worst wins: malformed > invalid > key-unknown).

Human output is Polish-first with English fallback (LANG detection; default
EN for non-PL locales). `lustro tracks narratives, not people` — output never
presents advisories as verdicts about individuals.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path

from . import __version__, crypto
from . import canon as canon_mod
from .fetch import FetchError, LustroFetcher

VERDICT_VALID = "valid"
VERDICT_INVALID = "invalid"
VERDICT_KEY_UNKNOWN = "key-unknown"
VERDICT_MALFORMED = "malformed"

EXIT_OK = 0
EXIT_INVALID = 1
EXIT_KEY_UNKNOWN = 2
EXIT_MALFORMED = 3

_STRINGS = {
    "en": {
        "verdict": "verdict",
        "record": "record",
        "scheme": "canon scheme",
        "key_source": "key source",
        "fingerprint": "key fingerprint (SHA-256)",
        "no_key": "no verification key available; verdict is key-unknown (exit 2)",
        "fallback_note": "note: /api/health reports classifier_loaded=false — confidence values use keyword-fallback scoring",
        "honest_note": "note: if this fails, the production canon convention may differ; see README signature-scheme assumptions",
    },
    "pl": {
        "verdict": "werdykt",
        "record": "rekord",
        "scheme": "schemat kanonizacji",
        "key_source": "źródło klucza",
        "fingerprint": "odcisk klucza (SHA-256)",
        "no_key": "brak klucza weryfikacyjnego; werdykt: key-unknown (kod 2)",
        "fallback_note": "uwaga: /api/health zgłasza classifier_loaded=false — wartości confidence pochodzą z prostego scoringu słów kluczowych",
        "honest_note": "uwaga: w razie niepowodzenia produkcyjny schemat kanonizacji może się różnić; patrz README",
    },
}


def _lang() -> str:
    lang = os.environ.get("LANG", "")
    return "pl" if lang.lower().startswith("pl") else "en"


def _t(key: str) -> str:
    return _STRINGS[_lang()].get(key, _STRINGS["en"][key])


def verify_record(
    record: dict,
    pubkey: bytes | None,
    scheme: str,
) -> dict:
    """Verify one advisory/correction dict. Returns a result dict with
    verdict, id, type, scheme, and optional detail."""
    result: dict = {
        "id": record.get("id") if isinstance(record, dict) else None,
        "type": canon_mod.detect_record_type(record) if isinstance(record, dict) else "unknown",
        "scheme": scheme,
        "verdict": VERDICT_MALFORMED,
    }
    if not isinstance(record, dict):
        result["detail"] = "record is not a JSON object"
        return result
    if "signature" not in record:
        result["detail"] = "missing signature field"
        return result
    try:
        payload = canon_mod.canonicalize(record, scheme)
    except canon_mod.CanonError as exc:
        result["detail"] = str(exc)
        return result
    try:
        crypto.decode_signature_b64(record.get("signature"))
    except crypto.MalformedSignatureError as exc:
        result["detail"] = str(exc)
        return result
    if pubkey is None:
        result["verdict"] = VERDICT_KEY_UNKNOWN
        result["detail"] = "no verification key available"
        return result
    try:
        ok = crypto.verify(payload, record.get("signature"), pubkey)
    except crypto.MalformedSignatureError as exc:
        result["verdict"] = VERDICT_MALFORMED
        result["detail"] = str(exc)
        return result
    result["verdict"] = VERDICT_VALID if ok else VERDICT_INVALID
    if not ok:
        result["detail"] = "signature does not match canonical payload"
    return result


def _verdict_exit(verdicts: list[str]) -> int:
    if any(v == VERDICT_MALFORMED for v in verdicts):
        return EXIT_MALFORMED
    if any(v == VERDICT_INVALID for v in verdicts):
        return EXIT_INVALID
    if any(v == VERDICT_KEY_UNKNOWN for v in verdicts):
        return EXIT_KEY_UNKNOWN
    return EXIT_OK


def _emit(result: dict, args, key_result: crypto.KeyResult | None) -> None:
    if args.json:
        out = dict(result)
        if key_result is not None:
            out["key_fingerprint"] = crypto.fingerprint(key_result.pubkey)
            out["key_source"] = key_result.source
        print(json.dumps(out, ensure_ascii=False, sort_keys=True))
        return
    print(f"{_t('verdict')}: {result['verdict']}")
    print(f"{_t('record')}: {result.get('type')} {result.get('id') or ''}".rstrip())
    print(f"{_t('scheme')}: {result.get('scheme')}")
    if result.get("detail"):
        print(f"detail: {result['detail']}")
    if args.verbose:
        if key_result is not None:
            print(f"{_t('key_source')}: {key_result.source}")
            print(f"{_t('fingerprint')}: {crypto.fingerprint(key_result.pubkey)}")
        else:
            print(_t("no_key"))
        if result["verdict"] == VERDICT_INVALID:
            print(_t("honest_note"))


def _resolve_key_or_none(args) -> crypto.KeyResult | None:
    try:
        return crypto.resolve_key(
            key_file=args.key_file,
            key_b64=args.key_b64,
            key_url=args.key_url,
            trust=args.trust_new_key,
            verbose=args.verbose,
        )
    except crypto.KeyUnavailableError as exc:
        if args.verbose and not args.json:
            print(f"{_t('no_key')}\ndetail: {exc}")
        return None


def _parse_json_input(text: str) -> object:
    """Parse JSON input; raises SystemExit(EXIT_MALFORMED) on bad JSON/empty."""
    if not text.strip():
        print("malformed input: empty", file=sys.stderr)
        raise SystemExit(EXIT_MALFORMED)
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        print(f"malformed input: invalid JSON: {exc}", file=sys.stderr)
        raise SystemExit(EXIT_MALFORMED) from exc


def _run_single(args, record: dict) -> int:
    key_result = _resolve_key_or_none(args)
    result = verify_record(record, key_result.pubkey if key_result else None, args.canon)
    _emit(result, args, key_result)
    return _verdict_exit([result["verdict"]])


def _cmd_file(args) -> int:
    if args.path == "-":
        text = sys.stdin.read()
    else:
        try:
            text = Path(args.path).read_text(encoding="utf-8")
        except OSError as exc:
            print(f"malformed input: cannot read {args.path}: {exc}", file=sys.stderr)
            return EXIT_MALFORMED
    doc = _parse_json_input(text)
    if isinstance(doc, dict) and isinstance(doc.get("items"), list):
        # auto-detected feed export → batch semantics
        return _run_batch(args, doc)
    if isinstance(doc, dict):
        return _run_single(args, doc)
    print("malformed input: expected a JSON object (advisory/correction) or feed export", file=sys.stderr)
    return EXIT_MALFORMED


def _cmd_fetch(args, kind: str) -> int:
    fetcher = LustroFetcher(base_url=args.base_url)
    try:
        if kind == "advisory":
            record = fetcher.get_advisory(args.id)
        else:
            record = fetcher.get_correction(args.id)
        if args.verbose and not args.json and fetcher.classifier_fallback():
            print(_t("fallback_note"))
    except FetchError as exc:
        print(f"fetch error: {exc}", file=sys.stderr)
        return EXIT_MALFORMED
    finally:
        fetcher.close()
    return _run_single(args, record)


def _build_report(results: list[dict], key_result: crypto.KeyResult | None, args) -> dict:
    counts = {
        VERDICT_VALID: 0,
        VERDICT_INVALID: 0,
        VERDICT_KEY_UNKNOWN: 0,
        VERDICT_MALFORMED: 0,
    }
    for r in results:
        counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1
    report: dict = {
        "tool": "lustro-verify",
        "tool_version": __version__,
        "generated_at": datetime.now(UTC).isoformat(),
        "canon_scheme": args.canon,
        "key_fingerprint": crypto.fingerprint(key_result.pubkey) if key_result else None,
        "key_source": key_result.source if key_result else None,
        "counts": counts,
        "total": len(results),
        "results": results,
        "note": "LUSTRO tracks narratives, not people. Verification results are "
        "statements about records, never about individuals.",
    }
    return report


def _finalize_report(report: dict, args) -> dict:
    """Sign the report with a local signing key if provided; otherwise attach a
    SHA-256 manifest hash (unsigned-but-hashed)."""
    body = dict(report)
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    digest = hashlib.sha256(canonical).hexdigest()
    if args.signing_key_file:
        try:
            priv_b64 = Path(args.signing_key_file).read_text(encoding="utf-8").strip()
            pad = (-len(priv_b64)) % 4
            priv_raw = base64.b64decode(priv_b64 + "=" * pad, validate=True)
            sig = crypto.sign(canonical, priv_raw)
            body["attestation"] = {
                "mode": "signed",
                "algorithm": "Ed25519",
                "payload_sha256": digest,
                "signature": sig,
            }
            return body
        except (OSError, ValueError, crypto.KeyUnavailableError) as exc:
            print(f"warning: could not sign attestation ({exc}); falling back to hashed manifest", file=sys.stderr)
    body["attestation"] = {
        "mode": "hashed",
        "payload_sha256": digest,
        "note": "unsigned; integrity via SHA-256 of the canonical report body",
    }
    return body


def _run_batch(args, doc: object) -> int:
    items = canon_mod.iter_feed_items(doc)
    if not items:
        print("malformed input: no verifiable items found in feed export", file=sys.stderr)
        return EXIT_MALFORMED
    key_result = _resolve_key_or_none(args)
    pubkey = key_result.pubkey if key_result else None
    results = [verify_record(it, pubkey, args.canon) for it in items]
    report = _finalize_report(_build_report(results, key_result, args), args)
    if args.json:
        print(json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2))
    else:
        c = report["counts"]
        print(
            f"batch: {report['total']} items — "
            f"valid={c[VERDICT_VALID]} invalid={c[VERDICT_INVALID]} "
            f"key-unknown={c[VERDICT_KEY_UNKNOWN]} malformed={c[VERDICT_MALFORMED]}"
        )
        for r in results:
            print(f"  {r['verdict']:>11}  {r.get('type')}:{r.get('id')}")
        att = report.get("attestation", {})
        print(f"attestation: {att.get('mode')} sha256={att.get('payload_sha256')}")
        if args.verbose:
            if key_result:
                print(f"{_t('fingerprint')}: {crypto.fingerprint(key_result.pubkey)}")
            else:
                print(_t("no_key"))
    return _verdict_exit([r["verdict"] for r in results])


def _cmd_batch(args) -> int:
    try:
        text = Path(args.path).read_text(encoding="utf-8")
    except OSError as exc:
        print(f"malformed input: cannot read {args.path}: {exc}", file=sys.stderr)
        return EXIT_MALFORMED
    doc = _parse_json_input(text)
    return _run_batch(args, doc)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="lustro-verify",
        description="Verify Ed25519 signatures on LUSTRO advisories/corrections. "
        "LUSTRO tracks narratives, not people.",
    )
    p.add_argument("--version", action="version", version=f"lustro-verify {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    def common(sp: argparse.ArgumentParser) -> None:
        sp.add_argument("--key-file", help="file with base64 raw 32-byte Ed25519 public key")
        sp.add_argument("--key-b64", help="base64 public key (or env LUSTRO_CORE_PUBLIC_KEY_B64)")
        sp.add_argument("--key-url", help="URL returning the base64 public key (TOFU-pinned)")
        sp.add_argument("--trust-new-key", action="store_true", help="override TOFU pin on key rotation")
        sp.add_argument(
            "--canon",
            choices=canon_mod.CANON_SCHEMES,
            default="json-minus-signature",
            help="canonicalization scheme to try",
        )
        sp.add_argument("--json", action="store_true", help="machine-readable JSON output")
        sp.add_argument("--verbose", "-v", action="store_true", help="verbose human output")
        sp.add_argument("--base-url", default="https://projektlustro.eu", help=argparse.SUPPRESS)

    for name in ("advisory", "correction"):
        sp = sub.add_parser(name, help=f"fetch and verify a {name} by id")
        sp.add_argument("id")
        common(sp)
    sp = sub.add_parser("file", help="verify raw JSON from file or stdin ('-')")
    sp.add_argument("path", help="path to JSON file, or '-' for stdin")
    common(sp)
    sp = sub.add_parser("batch", help="verify every item in a feed export; emit attestation report")
    sp.add_argument("path", help="feed export JSON ({items:[...]} or bare list)")
    sp.add_argument(
        "--signing-key-file",
        help="file with base64 raw 32-byte Ed25519 PRIVATE key to sign the attestation report",
    )
    common(sp)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "advisory":
        return _cmd_fetch(args, "advisory")
    if args.command == "correction":
        return _cmd_fetch(args, "correction")
    if args.command == "file":
        return _cmd_file(args)
    if args.command == "batch":
        return _cmd_batch(args)
    return EXIT_MALFORMED  # pragma: no cover


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
