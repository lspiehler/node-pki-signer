// Which SigningKey signs a request (ADR 0003): the backends that can reach the CA's key, in order of
// preference, and the first whose algorithm is allowlisted.
import type { KeyObject } from 'node:crypto';
import { basename } from 'node:path';
import { signatureAlgorithm } from './algorithms.ts';
import { allowlisted } from './allowlist.ts';
import { UnsupportedError } from './errors.ts';
import { kmsKey, type KmsClient } from './kms-key.ts';
import { opensslKey } from './openssl-key.ts';
import type { SignParams } from './options.ts';
import type { Pkcs11Sessions } from './pkcs11-key.ts';
import type { SigningKey } from './signing-key.ts';
import { softwareKey } from './software-key.ts';

export interface KeySettings {
  /** signature algorithms to leave to OpenSSL even though they're allowlisted, e.g. 'ML-DSA-65' */
  forceOpenSSL?: readonly string[];
  /** the backends that may sign, e.g. ['openssl-pkcs11'] to keep pkcs11js off a YubiKey; all by default */
  backends?: readonly string[];
  /** the long-lived PKCS#11 modules and logins; PKCS#11 keys go to OpenSSL without them */
  pkcs11?: Pkcs11Sessions;
  /** the long-lived KMS client; KMS keys go to OpenSSL without it */
  kms?: () => Promise<KmsClient>;
  /** the openssl binary of the OpenSSL backends */
  binpath?: string;
  /** replaces the allowlist, for the differential harness to try backends before they're allowlisted */
  allowlisted?: (backend: string) => ReadonlySet<string>;
}

type Candidate = [backend: string, load: () => SigningKey | Promise<SigningKey>];

/**
 * The key to sign `params` with. Throws UnsupportedError when no allowlisted backend can sign, so
 * the whole operation goes to node-openssl-cert2, and SignerError when the key itself is refused.
 */
export async function selectKey(params: SignParams, issuerKey: KeyObject, settings: KeySettings): Promise<SigningKey> {
  const hash = params.options.hash ?? 'sha256';
  const algorithm = signatureAlgorithm(issuerKey, hash);
  if (settings.forceOpenSSL?.includes(algorithm)) {
    throw new UnsupportedError('check allowlist', `${algorithm} is set to sign with OpenSSL`);
  }
  const publicKey = new Uint8Array(issuerKey.export({ type: 'spki', format: 'der' }));
  const { pkcs11, kms, binpath } = settings;

  let candidates: Candidate[];
  if (params.kms?.keyVersion) {
    const { keyVersion } = params.kms;
    candidates = [
      [
        'kms',
        async () => {
          if (!kms) throw new UnsupportedError('load CA key', 'KMS keys need a KMS client');
          return kmsKey(await kms(), keyVersion, algorithm, publicKey);
        },
      ],
    ];
  } else if (params.pkcs11) {
    const ref = params.pkcs11;
    // libkmsp11's keys are signed with the KMS API, which needs the key version's name
    if (basename(ref.modulePath) === 'libkmsp11.so') {
      throw new UnsupportedError('load CA key', 'Google KMS keys without kms.keyVersion');
    }
    candidates = [
      [
        'pkcs11',
        () => {
          if (!pkcs11) throw new UnsupportedError('load CA key', 'PKCS#11 keys need PKCS#11 sessions');
          return pkcs11.key(ref, algorithm, publicKey);
        },
      ],
      ['openssl-pkcs11', () => opensslKey({ pkcs11: ref }, algorithm, publicKey, binpath)],
    ];
  } else {
    candidates = [
      ['software', () => softwareKey(params.key, params.password, hash)],
      ['openssl', () => opensslKey({ pem: params.key, passphrase: params.password }, algorithm, publicKey, binpath)],
    ];
  }

  const usable = candidates.filter(([backend]) => !settings.backends || settings.backends.includes(backend));
  let unsupported: UnsupportedError | undefined;
  for (const [backend, load] of usable) {
    if (!(settings.allowlisted ?? allowlisted)(backend).has(algorithm)) continue;
    try {
      return await load();
    } catch (err) {
      // e.g. pkcs11js isn't installed: the next backend may do
      if (!(err instanceof UnsupportedError)) throw err;
      unsupported ??= err;
    }
  }
  throw (
    unsupported ??
    new UnsupportedError(
      'check allowlist',
      `${algorithm} with ${usable.map(([backend]) => backend).join(' or ') || 'no'} keys isn't allowlisted`,
    )
  );
}
