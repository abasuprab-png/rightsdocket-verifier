#!/usr/bin/env python3
"""
RightsDocket Verifier — Reference Implementation (Python)

Usage:
    python verifier.py <path-to-assertion.json>

Exit codes:
    0 = VALID, 1 = INVALID, 2 = ERROR

Dependencies: pip install pynacl
Spec: https://www.rightsdocket.com/verify
"""
import base64
import json
import os
import sys
import urllib.request
from typing import Any

import nacl.signing
import nacl.exceptions

JWKS_URL = os.getenv(
    'RIGHTSDOCKET_JWKS_URL',
    'https://www.rightsdocket.com/.well-known/jwks.json'
)


def b64url_decode(s: str) -> bytes:
    s += '=' * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


def canonicalize(obj: Any) -> str:
    """Minimal RFC 8785 JCS-compatible canonicalization."""
    if obj is None or isinstance(obj, (bool, int, float, str)):
        return json.dumps(obj, separators=(',', ':'), ensure_ascii=False)
    if isinstance(obj, list):
        return '[' + ','.join(canonicalize(x) for x in obj) + ']'
    if isinstance(obj, dict):
        items = sorted(obj.items())
        return '{' + ','.join(
            json.dumps(k, separators=(',', ':')) + ':' + canonicalize(v)
            for k, v in items
        ) + '}'
    raise TypeError(f'Unsupported type: {type(obj)}')


def fetch_jwks() -> dict:
    with urllib.request.urlopen(JWKS_URL, timeout=10) as r:
        return json.loads(r.read())


def verify(assertion_path: str) -> dict:
    with open(assertion_path) as f:
        assertion = json.load(f)

    kid = assertion.get('key_id') or assertion.get('kid')
    sig_b64 = assertion.get('signature')
    payload = assertion.get('payload')
    tsr = assertion.get('timestamp') or assertion.get('tsr')

    if not (kid and sig_b64 and payload):
        return {'valid': False, 'reason': 'assertion missing key_id, signature, or payload'}

    jwks = fetch_jwks()
    jwk = next((k for k in jwks['keys'] if k.get('kid') == kid), None)
    if not jwk:
        return {'valid': False, 'reason': f'key_id {kid} not found in published JWKS'}
    if jwk.get('kty') != 'OKP' or jwk.get('crv') != 'Ed25519':
        return {'valid': False, 'reason': f'unexpected key type for {kid}'}

    pub_bytes = b64url_decode(jwk['x'])
    verify_key = nacl.signing.VerifyKey(pub_bytes)

    canonical = canonicalize(payload)
    signature = b64url_decode(sig_b64)

    try:
        verify_key.verify(canonical.encode('utf-8'), signature)
        sig_valid = True
    except nacl.exceptions.BadSignatureError:
        sig_valid = False

    has_timestamp = bool(tsr) and len(tsr) > 100

    return {
        'valid': sig_valid and has_timestamp,
        'signature_valid': sig_valid,
        'timestamp_present': has_timestamp,
        'key_id': kid,
        'fingerprint_jws': jwk.get('x5t#S256'),
        'reason': 'OK' if (sig_valid and has_timestamp) else (
            'missing or empty timestamp' if sig_valid else 'signature did not verify'
        ),
    }


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print('Usage: python verifier.py <assertion.json>', file=sys.stderr)
        sys.exit(2)

    try:
        result = verify(sys.argv[1])
        print(json.dumps(result, indent=2))
        sys.exit(0 if result['valid'] else 1)
    except Exception as e:
        print(f'ERROR: {e}', file=sys.stderr)
        sys.exit(2)
