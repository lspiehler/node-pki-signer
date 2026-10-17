// A CA key held in memory (PKIaaS.io software CAs), signing with node:crypto.
import { createPrivateKey, createPublicKey, sign, type KeyObject } from 'node:crypto';
import { promisify } from 'node:util';
import { SignerError, UnsupportedError } from './errors.ts';
import type { SigningKey } from './signing-key.ts';

const signAsync = promisify(sign);

// the hashes PKIaaS.io offers; 'default' is OpenSSL's default for the key type
const hashes = new Set(['sha1', 'sha256', 'sha384', 'sha512', 'default']);

// the algorithm for each key type and hash, as `openssl ca -md <hash>` signs with it
function signatureAlgorithm(key: KeyObject, hash: string): { name: string; digest: string | null } {
  if (!hashes.has(hash)) throw new UnsupportedError('load CA key', `hash ${hash}`);
  const digest = hash === 'default' ? 'sha256' : hash;
  const type = key.asymmetricKeyType ?? '';
  if (type === 'rsa') return { name: `${digest}WithRSAEncryption`, digest };
  if (type === 'ec') return { name: `ecdsa-with-${digest.toUpperCase()}`, digest };
  // ML-DSA and SLH-DSA sign the message itself, and OpenSSL ignores the hash
  if (/^(ml-dsa|slh-dsa)-/.test(type)) {
    // e.g. slh-dsa-sha2-128s is SLH-DSA-SHA2-128s
    return { name: type.toUpperCase().replace(/[SF]$/, (s) => s.toLowerCase()), digest: null };
  }
  throw new UnsupportedError('load CA key', `key type ${type || 'unknown'}`);
}

/** A SigningKey for a PEM private key, encrypted or not, signing with `hash` (default sha256). */
export function softwareKey(pem: string, passphrase: string | undefined, hash = 'sha256'): SigningKey {
  let key: KeyObject;
  try {
    key = createPrivateKey({ key: pem, format: 'pem', ...(passphrase ? { passphrase } : {}) });
  } catch (err) {
    // the cause can quote the key or passphrase, so leave it out
    throw new SignerError('load CA key', `can't read the private key (${(err as { code?: string }).code ?? 'error'})`);
  }
  const { name, digest } = signatureAlgorithm(key, hash);
  const spki = createPublicKey(key).export({ type: 'spki', format: 'der' });
  return {
    backend: 'software',
    algorithm: name,
    publicKey: () => Promise.resolve(new Uint8Array(spki)),
    async sign(tbs) {
      try {
        return new Uint8Array(await signAsync(digest, tbs, key));
      } catch (err) {
        throw new SignerError('sign', err instanceof Error ? err.message : String(err));
      }
    },
  };
}
