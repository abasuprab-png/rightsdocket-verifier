# rightsdocket-verifier

Reference implementation for verifying [RightsDocket](https://www.rightsdocket.com) copyright provenance assertions. Available in **Node.js** and **Python**.

> **Status:** reference implementation. Production users should harden according to their threat model — see "Hardening checklist" below.

## What this verifies

A RightsDocket assertion is a JSON document signed with an Ed25519 keypair, with an embedded RFC 3161 timestamp. This verifier confirms:

1. **Signature.** Ed25519 signature over the canonical (RFC 8785 JCS) payload, verified against the public key published at `/.well-known/jwks.json`.
2. **Key identity.** The `key_id` referenced in the assertion exists in published JWKS and is type Ed25519.
3. **Timestamp presence.** RFC 3161 timestamp field is non-empty.

## Quick start

### Node.js

```bash
npm install
node verifier.mjs path/to/assertion.json
```

### Python

```bash
pip install -r requirements.txt
python verifier.py path/to/assertion.json
```

## Output

```json
{
  "valid": true,
  "signature_valid": true,
  "timestamp_present": true,
  "key_id": "rd-sign-2026-05-06",
  "fingerprint_jws": "yPzfRZEnKEZ6VCJKepMiCAC8CUdYPHB1PRffW_wVvJ4",
  "reason": "OK"
}
```

**Exit codes:** `0` (VALID), `1` (INVALID), `2` (ERROR).

## Public key fingerprints (for audit)

The current production signing key (`rd-sign-2026-05-06`, activated 2026-05-06):

| Format | Value |
|---|---|
| SHA-256 of decoded DER bytes | `c8fcdf45912728467a54224a7a93220800bc0947583c70753d17df5bfc15bc9e` |
| SHA-256 of base64-encoded DER string | `51ff0e723bf96bd4925b3fdd278ca303e048402d41e1297246104d8a41acd62c` |
| JWS thumbprint (x5t#S256) | `yPzfRZEnKEZ6VCJKepMiCAC8CUdYPHB1PRffW_wVvJ4` |

These fingerprints are also published at [`/.well-known/signing-keys`](https://www.rightsdocket.com/.well-known/signing-keys) and are the canonical reference.

## What this does NOT verify

- **Full RFC 3161 timestamp chain.** Production verifiers should validate the TSR signature against the TSA's certificate chain.
- **Revocation.** Check [`/.well-known/signing-keys-changelog`](https://www.rightsdocket.com/.well-known/signing-keys-changelog) for retired or revoked keys.
- **Key expiry.** Compare timestamp to the key's `expiration_date` in JWKS.
- **C2PA manifest semantics.** This verifies the cryptographic envelope; semantic claims about the asserted content require C2PA-aware tooling.

## Hardening checklist for production

- [ ] Pin TLS to a known CA when fetching JWKS (avoid TLS-MITM)
- [ ] Cache JWKS locally with a max age (avoid hot-loop fetches)
- [ ] Use a dedicated JCS library (e.g., `canonicalize` npm pkg, `rfc8785` python pkg) instead of the inline canonicalize() — production-grade JCS handles edge cases
- [ ] Add full RFC 3161 timestamp chain validation
- [ ] Check the changelog before accepting a key_id

## EU AI Act Article 50 alignment

RightsDocket signs every provenance assertion with the keys published at `/.well-known/jwks.json`. Operators of generative AI systems can use this verifier to confirm the origin of any RightsDocket-issued assertion without contacting RightsDocket. See `/.well-known/signing-keys.compliance.eu_ai_act` for the canonical disclosure.

## License

[Apache-2.0](LICENSE). Use freely.

## Reporting issues

- **Bugs in this reference verifier:** [open a GitHub issue](https://github.com/abasuprab-png/rightsdocket-verifier/issues).
- **Suspected key compromise or signature forgery (P0):** `security@signalfidelitygroup.com` — see [security.txt](https://www.rightsdocket.com/.well-known/security.txt).

## Related links

- [RightsDocket Verify page](https://www.rightsdocket.com/verify) — human-readable verification guide
- [JWKS](https://www.rightsdocket.com/.well-known/jwks.json) — public key material
- [Signing keys + JSON-LD](https://www.rightsdocket.com/.well-known/signing-keys) — compliance metadata
- [Signing keys changelog](https://www.rightsdocket.com/.well-known/signing-keys-changelog) — rotation history
