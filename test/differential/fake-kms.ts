// A stand-in for Google Cloud KMS's asymmetricSign, holding the corpus CA keys. It refuses what KMS
// refuses (a digest for PQC keys, data for RSA and EC keys, a digest that isn't the key's) and signs
// a digest the way KMS does, with `openssl pkeyutl` on the digest itself.
import { execFile } from 'node:child_process';
import { createPrivateKey, sign, type KeyObject } from 'node:crypto';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { KmsClient } from '../../src/kms-key.ts';

// the digest each KMS EC key signs; RSA PKCS#1 keys come with SHA-256 or SHA-512
const ecDigests: Record<string, string> = { prime256v1: 'sha256', secp384r1: 'sha384' };
const pqc = new Set(['ml-dsa-44', 'ml-dsa-65', 'ml-dsa-87', 'slh-dsa-sha2-128s']);

/** Which corpus CA key types and hashes KMS can sign: what the kms backend is tested with. */
export function kmsSupports(type: string, curve: string | undefined, hash: string | null): boolean {
  if (type === 'rsa') return hash === 'sha256' || hash === 'sha512';
  if (type === 'ec') return curve !== undefined && ecDigests[curve] === hash;
  return pqc.has(type) && hash === null;
}

function pkeyutlSign(key: KeyObject, hash: string, digest: Uint8Array): Promise<Uint8Array> {
  return mkdtemp(join(tmpdir(), 'pki-signer-kms-')).then(async (dir) => {
    try {
      await writeFile(join(dir, 'key.pem'), key.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
      return await new Promise<Uint8Array>((resolve, reject) => {
        const args = ['pkeyutl', '-sign', '-inkey', join(dir, 'key.pem'), '-pkeyopt', `digest:${hash}`];
        const child = execFile('openssl', args, { encoding: 'buffer' }, (err, stdout, stderr) => {
          if (err) reject(new Error(`3 INVALID_ARGUMENT: ${stderr.toString()}`));
          else resolve(new Uint8Array(stdout));
        });
        child.stdin?.end(digest);
      });
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
}

export class FakeKms implements KmsClient {
  #keys = new Map<string, KeyObject>();
  requests: { name: string; digest?: string; data?: boolean }[] = [];

  /** Adds a CA key and returns its key version name. */
  add(pem: string, passphrase: string): string {
    const name = `projects/p/locations/global/keyRings/r/cryptoKeys/ca${this.#keys.size + 1}/cryptoKeyVersions/1`;
    this.#keys.set(name, createPrivateKey({ key: pem, passphrase }));
    return name;
  }

  async asymmetricSign(request: Parameters<KmsClient['asymmetricSign']>[0]) {
    const key = this.#keys.get(request.name);
    if (!key) throw new Error(`5 NOT_FOUND: ${request.name}`);
    const [hash, digest] = Object.entries(request.digest ?? {})[0] ?? [];
    this.requests.push({
      name: request.name,
      ...(hash ? { digest: hash } : {}),
      ...(request.data ? { data: true } : {}),
    });
    const type = key.asymmetricKeyType ?? '';
    if (!kmsSupports(type, key.asymmetricKeyDetails?.namedCurve, hash ?? null)) {
      throw new Error(`3 INVALID_ARGUMENT: the key can't sign ${hash ?? 'data'}`);
    }
    if (hash && digest) return [{ signature: await pkeyutlSign(key, hash, digest) }] as [{ signature: Uint8Array }];
    if (!request.data) throw new Error('3 INVALID_ARGUMENT: no data');
    return [{ signature: new Uint8Array(sign(null, request.data, key)) }] as [{ signature: Uint8Array }];
  }
}
