// The algorithm × backend pairs the native path may sign with (ADR 0001): only those the
// differential harness has passed against OpenSSL. Everything else falls back to OpenSSL.

// every CA key type PKIaaS.io offers, with every hash (test/differential/differential.test.ts)
const everyCAKey: ReadonlySet<string> = new Set([
  'sha1WithRSAEncryption',
  'sha224WithRSAEncryption',
  'sha256WithRSAEncryption',
  'sha384WithRSAEncryption',
  'sha512WithRSAEncryption',
  'ecdsa-with-SHA1',
  'ecdsa-with-SHA224',
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
]);

// RSA and ECDSA, which SoftHSM signs (test/differential/backends.test.ts)
const classical: ReadonlySet<string> = new Set([...everyCAKey].filter((a) => /RSA|ecdsa/.test(a)));

const allowlist: Record<string, ReadonlySet<string>> = {
  software: everyCAKey,
  // the CA's PEM key, signed by `openssl dgst` (ADR 0003)
  openssl: everyCAKey,
  // keys on a token, through pkcs11js and through openssl with pkcs11-provider
  pkcs11: classical,
  'openssl-pkcs11': classical,
  // Google Cloud KMS: what a test against the real service passed (test/live/kms.test.ts, ADR 0003)
  kms: new Set(['sha256WithRSAEncryption']),
};

/** The signature algorithms allowlisted for a backend. */
export function allowlisted(backend: string): ReadonlySet<string> {
  return allowlist[backend] ?? new Set();
}
