// Signature algorithms: how a SigningKey's algorithm appears in a certificate, and how to verify
// a CSR's self-signature.
import { AlgorithmIdentifier } from '@peculiar/asn1-x509';
import { UnsupportedError } from './errors.ts';

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

/** The AlgorithmIdentifier for a signature algorithm name, e.g. 'sha256WithRSAEncryption'. */
export function algorithmIdentifier(name: string): AlgorithmIdentifier {
  const algorithm = algorithms[name];
  if (!algorithm) throw new UnsupportedError('build TBS', `no signature algorithm ${name}`);
  return new AlgorithmIdentifier({
    algorithm: algorithm.oid,
    ...(algorithm.nullParameters ? { parameters: null } : {}),
  });
}

/** The hash node:crypto needs to verify a signature with this algorithm OID (null: none). */
export function verifyHash(oid: string): string | null {
  for (const algorithm of Object.values(algorithms)) {
    if (algorithm.oid === oid) return algorithm.hash;
  }
  throw new UnsupportedError('verify CSR signature', `no signature algorithm ${oid}`);
}
