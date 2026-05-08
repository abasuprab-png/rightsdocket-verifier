#!/usr/bin/env node
/**
 * RightsDocket Verifier — Reference Implementation
 *
 * Usage:
 *   node verifier.mjs <path-to-assertion.json>
 *
 * Exit codes:
 *   0 = VALID, 1 = INVALID, 2 = ERROR
 *
 * Dependencies: npm install @noble/ed25519 @noble/hashes
 * Spec: https://www.rightsdocket.com/verify
 */

import * as ed from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha512';
import { readFileSync } from 'node:fs';

ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));

const JWKS_URL = process.env.RIGHTSDOCKET_JWKS_URL
  ?? 'https://www.rightsdocket.com/.well-known/jwks.json';

function b64urlToBytes(b64url) {
  const b64 = b64url.replace(/-/g, '+').replace(/_/g, '/');
  const padded = b64 + '='.repeat((4 - (b64.length % 4)) % 4);
  return new Uint8Array(Buffer.from(padded, 'base64'));
}

function canonicalize(obj) {
  if (obj === null || typeof obj !== 'object') return JSON.stringify(obj);
  if (Array.isArray(obj)) return '[' + obj.map(canonicalize).join(',') + ']';
  const keys = Object.keys(obj).sort();
  return '{' + keys.map(k => JSON.stringify(k) + ':' + canonicalize(obj[k])).join(',') + '}';
}

async function fetchJwks() {
  const res = await fetch(JWKS_URL);
  if (!res.ok) throw new Error(`JWKS fetch failed: ${res.status}`);
  return res.json();
}

async function verify(assertionPath) {
  const raw = readFileSync(assertionPath, 'utf8');
  const assertion = JSON.parse(raw);
  const kid = assertion.key_id ?? assertion.kid;
  const sigB64 = assertion.signature;
  const payload = assertion.payload;
  const tsr = assertion.timestamp ?? assertion.tsr;

  if (!kid || !sigB64 || !payload) {
    throw new Error('assertion missing key_id, signature, or payload');
  }

  const jwks = await fetchJwks();
  const jwk = jwks.keys.find(k => k.kid === kid);
  if (!jwk) {
    return { valid: false, reason: `key_id ${kid} not found in published JWKS` };
  }
  if (jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519') {
    return { valid: false, reason: `unexpected key type for ${kid}` };
  }

  const pubKey = b64urlToBytes(jwk.x);
  const canonical = canonicalize(payload);
  const message = new TextEncoder().encode(canonical);
  const signature = b64urlToBytes(sigB64);

  const valid = await ed.verifyAsync(signature, message, pubKey);
  const hasTimestamp = !!tsr && tsr.length > 100;

  return {
    valid: valid && hasTimestamp,
    signature_valid: valid,
    timestamp_present: hasTimestamp,
    key_id: kid,
    fingerprint_jws: jwk['x5t#S256'],
    reason: valid && hasTimestamp ? 'OK' : (valid ? 'missing or empty timestamp' : 'signature did not verify'),
  };
}

const path = process.argv[2];
if (!path) {
  console.error('Usage: node verifier.mjs <assertion.json>');
  process.exit(2);
}

verify(path)
  .then(result => {
    console.log(JSON.stringify(result, null, 2));
    process.exit(result.valid ? 0 : 1);
  })
  .catch(err => {
    console.error('ERROR:', err.message);
    process.exit(2);
  });
