// A CA key held in memory (PKIaaS.io software CAs), signing with node:crypto.
import { createPrivateKey, createPublicKey, sign, type KeyObject } from 'node:crypto';
import { promisify } from 'node:util';
import { signatureAlgorithm, signatureHash } from './algorithms.ts';
import { SignerError } from './errors.ts';
import type { SigningKey } from './signing-key.ts';

const signAsync = promisify(sign);

/** A SigningKey for a PEM private key, encrypted or not, signing with `hash` (default sha256). */
export function softwareKey(pem: string, passphrase: string | undefined, hash = 'sha256'): SigningKey {
  let key: KeyObject;
  try {
    key = createPrivateKey({ key: pem, format: 'pem', ...(passphrase ? { passphrase } : {}) });
  } catch (err) {
    // the cause can quote the key or passphrase, so leave it out
    throw new SignerError('load CA key', `can't read the private key (${(err as { code?: string }).code ?? 'error'})`);
  }
  const name = signatureAlgorithm(key, hash);
  const digest = signatureHash(name);
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
