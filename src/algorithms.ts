// Signature algorithms: how a SigningKey's algorithm appears in a certificate, and how to verify
// a CSR's self-signature.
import { AlgorithmIdentifier } from '@peculiar/asn1-x509';
import type { KeyObject } from 'node:crypto';
import { SignerError, UnsupportedError } from './errors.ts';

const rsa = '1.2.840.113549.1.1';
const ecdsa = '1.2.840.10045.4';
const nistSigAlgs = '2.16.840.1.101.3.4.3';

// the hash, or null for algorithms that sign the message itself
const algorithms: Record<string, { oid: string; hash: string | null; nullParameters?: boolean }> = {
  sha1WithRSAEncryption: { oid: `${rsa}.5`, hash: 'sha1', nullParameters: true },
  sha224WithRSAEncryption: { oid: `${rsa}.14`, hash: 'sha224', nullParameters: true },
  sha256WithRSAEncryption: { oid: `${rsa}.11`, hash: 'sha256', nullParameters: true },
  sha384WithRSAEncryption: { oid: `${rsa}.12`, hash: 'sha384', nullParameters: true },
  sha512WithRSAEncryption: { oid: `${rsa}.13`, hash: 'sha512', nullParameters: true },
  'ecdsa-with-SHA1': { oid: `${ecdsa}.1`, hash: 'sha1' },
  'ecdsa-with-SHA224': { oid: `${ecdsa}.3.1`, hash: 'sha224' },
  'ecdsa-with-SHA256': { oid: `${ecdsa}.3.2`, hash: 'sha256' },
  'ecdsa-with-SHA384': { oid: `${ecdsa}.3.3`, hash: 'sha384' },
  'ecdsa-with-SHA512': { oid: `${ecdsa}.3.4`, hash: 'sha512' },
  Ed25519: { oid: '1.3.101.112', hash: null },
  Ed448: { oid: '1.3.101.113', hash: null },
  // FIPS 204 and 205, in the order of their OIDs
  ...Object.fromEntries(
    [
      'ML-DSA-44',
      'ML-DSA-65',
      'ML-DSA-87',
      ...['SHA2', 'SHAKE'].flatMap((hash) =>
        ['128', '192', '256'].flatMap((bits) => ['s', 'f'].map((speed) => `SLH-DSA-${hash}-${bits}${speed}`)),
      ),
    ].map((name, i) => [name, { oid: `${nistSigAlgs}.${17 + i}`, hash: null }]),
  ),
};

// the hashes PKIaaS.io offers; 'default' is OpenSSL's default for the key type
const hashes = new Set(['sha1', 'sha224', 'sha256', 'sha384', 'sha512', 'default']);

/** The algorithm a key of this type signs with as `openssl ca -md <hash>` does, from its private or public key. */
export function signatureAlgorithm(key: KeyObject, hash: string): string {
  if (!hashes.has(hash)) throw new UnsupportedError('load CA key', `hash ${hash}`);
  const digest = hash === 'default' ? 'sha256' : hash;
  const type = key.asymmetricKeyType ?? '';
  if (type === 'rsa') return `${digest}WithRSAEncryption`;
  if (type === 'ec') return `ecdsa-with-${digest.toUpperCase()}`;
  // ML-DSA and SLH-DSA sign the message itself, and OpenSSL ignores the hash
  // e.g. slh-dsa-sha2-128s is SLH-DSA-SHA2-128s
  if (/^(ml-dsa|slh-dsa)-/.test(type)) return type.toUpperCase().replace(/[SF]$/, (s) => s.toLowerCase());
  throw new UnsupportedError('load CA key', `key type ${type || 'unknown'}`);
}

/** The hash a signature algorithm signs a digest of, or null when it signs the message itself. */
export function signatureHash(name: string): string | null {
  const algorithm = algorithms[name];
  if (!algorithm) throw new UnsupportedError('load CA key', `no signature algorithm ${name}`);
  return algorithm.hash;
}

/** The AlgorithmIdentifier for a signature algorithm name, e.g. 'sha256WithRSAEncryption'. */
export function algorithmIdentifier(name: string): AlgorithmIdentifier {
  const algorithm = algorithms[name];
  if (!algorithm) throw new UnsupportedError('build TBS', `no signature algorithm ${name}`);
  return new AlgorithmIdentifier({
    algorithm: algorithm.oid,
    ...(algorithm.nullParameters ? { parameters: null } : {}),
  });
}

// node:crypto's asymmetricKeyType for the key an algorithm signs with, e.g. ML-DSA-65 is ml-dsa-65
const keyType = (name: string): string =>
  name.endsWith('WithRSAEncryption') ? 'rsa' : name.startsWith('ecdsa-') ? 'ec' : name.toLowerCase();

/**
 * The hash node:crypto needs to verify a signature with this algorithm OID (null: none). With `key`, the
 * algorithm must be one for its type, as `openssl req -verify` requires: node:crypto would verify with whatever
 * the key implies.
 */
export function verifyHash(oid: string, key?: KeyObject): string | null {
  for (const [name, algorithm] of Object.entries(algorithms)) {
    if (algorithm.oid !== oid) continue;
    const type = key?.asymmetricKeyType;
    if (key && type !== keyType(name)) {
      // e.g. an RSA-PSS key; leave it to OpenSSL
      if (!type || !Object.keys(algorithms).some((other) => keyType(other) === type)) {
        throw new UnsupportedError('verify CSR signature', `key type ${type ?? 'unknown'}`);
      }
      throw new SignerError('verify CSR signature', `the signature algorithm ${name} is not for a ${type} key`);
    }
    return algorithm.hash;
  }
  throw new UnsupportedError('verify CSR signature', `no signature algorithm ${oid}`);
}
