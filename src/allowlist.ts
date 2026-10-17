// The algorithm × backend pairs the native path may sign with (ADR 0001): only those the
// differential harness has passed against OpenSSL. Everything else falls back to OpenSSL.
import { UnsupportedError } from './errors.ts';
import type { SigningKey } from './signing-key.ts';

const allowlist: Record<string, ReadonlySet<string>> = {
  software: new Set([
    'sha1WithRSAEncryption',
    'sha256WithRSAEncryption',
    'sha384WithRSAEncryption',
    'sha512WithRSAEncryption',
    'ecdsa-with-SHA1',
    'ecdsa-with-SHA256',
    'ecdsa-with-SHA384',
    'ecdsa-with-SHA512',
    'ML-DSA-44',
    'ML-DSA-65',
    'ML-DSA-87',
    'SLH-DSA-SHA2-128s',
    'SLH-DSA-SHA2-128f',
    'SLH-DSA-SHA2-192s',
    'SLH-DSA-SHA2-192f',
    'SLH-DSA-SHA2-256s',
    'SLH-DSA-SHA2-256f',
    'SLH-DSA-SHAKE-128s',
    'SLH-DSA-SHAKE-128f',
    'SLH-DSA-SHAKE-192s',
    'SLH-DSA-SHAKE-192f',
    'SLH-DSA-SHAKE-256s',
    'SLH-DSA-SHAKE-256f',
  ]),
};

/** The signature algorithms allowlisted for a backend. */
export function allowlisted(backend: string): ReadonlySet<string> {
  return allowlist[backend] ?? new Set();
}

/** Throws UnsupportedError unless `key` may sign natively: allowlisted and not forced to OpenSSL. */
export function checkAllowlist(key: SigningKey, forceOpenSSL: readonly string[] = []): void {
  if (forceOpenSSL.includes(key.algorithm)) {
    throw new UnsupportedError('check allowlist', `${key.algorithm} is set to sign with OpenSSL`);
  }
  if (!allowlisted(key.backend).has(key.algorithm)) {
    throw new UnsupportedError('check allowlist', `${key.algorithm} with ${key.backend} keys isn't allowlisted`);
  }
}
