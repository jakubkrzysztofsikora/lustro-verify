LUSTRO-VERIFY(1)              General Commands Manual             LUSTRO-VERIFY(1)

NAME
    lustro-verify — offline Ed25519 signature verification for LUSTRO
    advisories and corrections

SYNOPSIS
    lustro-verify advisory <id> [--key-file F | --key-b64 B | --key-url U]
        [--canon SCHEME] [--json] [--verbose]
    lustro-verify correction <id> [options]
    lustro-verify file <path|- > [options]
    lustro-verify batch <feed-export.json> [--signing-key-file F] [options]
    lustro-verify --version

DESCRIPTION
    lustro-verify verifies the cryptographic signatures that LUSTRO
    (https://projektlustro.eu) attaches to every advisory and correction in
    its public, key-less read API. It works on records fetched live from the
    API, on raw JSON files, on stdin, and on whole feed exports (batch mode
    with a signed-or-hashed attestation report — useful for mirrors and
    archives).

    Signatures are Ed25519 over a canonical reconstruction of the record.
    The signature field is base64, decoding to 64 raw bytes. The public key
    is a raw 32-byte Ed25519 key, base64-encoded.

    HARD-RULES COMPLIANCE: LUSTRO tracks narratives, not people. This tool
    never attempts author re-identification and never presents advisories as
    verdicts about individuals. Data is de-identified by design. When
    /api/health reports classifier_loaded=false, verbose fetch-mode output
    labels confidence values as "keyword-fallback scoring".

OPTIONS
    --key-file FILE
        Read the base64 public key from FILE. Highest priority.
    --key-b64 B64
        Public key inline. The environment variable
        LUSTRO_CORE_PUBLIC_KEY_B64 is an equivalent fallback.
    --key-url URL
        Fetch the public key from URL. The key's SHA-256 fingerprint is
        displayed and pinned (trust-on-first-use) in
        ~/.config/lustro-verify/known_keys. A later fingerprint mismatch is
        fatal unless --trust-new-key is given.
    --trust-new-key
        Override a TOFU pin mismatch (expected key rotation).
    --canon SCHEME
        Canonicalization scheme: json-minus-signature (default),
        json-with-null-signature.
    --signing-key-file FILE
        (batch only) base64 raw 32-byte Ed25519 PRIVATE key used to sign the
        attestation report. Without it, the report is unsigned but carries a
        SHA-256 manifest hash.
    --json      Machine-readable JSON output.
    --verbose   Extra human output (key source, fingerprint, notes).
    --version   Print version and exit.

SIGNATURE-SCHEME ASSUMPTIONS
    The exact production canon convention has NOT been empirically confirmed
    because no production verification key is publicly obtainable (see KEY
    ACQUISITION). The default candidate, documented for cross-checking, is:

        JSON of the record minus the `signature` field, keys sorted,
        separators=(',', ':'), ensure_ascii=False, UTF-8.

    The scheme tried is always included in the output. If a record signed by
    LUSTRO fails verification under this scheme, that is reported honestly as
    `invalid` with a note that the production convention may differ — this
    tool never claims `valid` it cannot prove.

KEY ACQUISITION
    Recon (2026-07-27): the OCI image ghcr.io/projektlustro/node-agent ships
    fail-closed — its embedded LUSTRO_NODE_AGENT_PINNED_KEY_B64 is EMPTY, and
    the only key present is a dev key gated by LUSTRO_NODE_AGENT_DEV=1 that
    does not verify live advisories. The production key is therefore NOT
    programmatically obtainable and must be injected by the operator via
    --key-file, --key-b64 / LUSTRO_CORE_PUBLIC_KEY_B64, or --key-url (TOFU).
    To inspect the image yourself:

        docker run --rm ghcr.io/projektlustro/node-agent env | grep KEY

    With no key configured, every verdict is `key-unknown` and the exit
    status is 2 — never a silent pass.

EXIT STATUS
    0   signature valid (batch: all items valid)
    1   signature invalid (batch: at least one invalid)
    2   verification key unavailable (verdict key-unknown)
    3   malformed input: bad JSON, missing/undecodable signature, unreadable
        file (batch: at least one malformed)
    Batch exit: worst wins (malformed > invalid > key-unknown).

EXAMPLES
    Verify an advisory straight from the API:
        LUSTRO_CORE_PUBLIC_KEY_B64='…' lustro-verify advisory 42 --verbose

    Verify a saved record, JSON output:
        lustro-verify file advisory-42.json --key-file lustro-core.pub --json

    Pipe a record via stdin:
        curl -s https://projektlustro.eu/v1/advisory/42 | lustro-verify file -

    Batch-verify a feed export and produce an attestation report:
        lustro-verify batch feed-export.json --json > attestation.json

    Batch-verify and sign the report with a local key:
        lustro-verify batch feed-export.json --signing-key-file mirror-sign.key

    Pin a key fetched from a trusted URL:
        lustro-verify advisory 42 --key-url https://keys.example/lustro-core.b64

NETWORK BEHAVIOR
    Fetch mode uses a token bucket capped at 25 req/min (the API allows 30),
    honors 429 Retry-After with jittered backoff, and parses defensively
    (tolerating extra/missing fields, 422/429). Unit tests use no network.

AUTHOR
    Projekt LUSTRO — https://projektlustro.eu · MIT License.
