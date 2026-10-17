// Keys in Google Cloud KMS, signing with the KMS API's asymmetricSign (ADR 0001, ADR 0003) instead
// of libkmsp11: one long-lived client per process, one RPC per signature.
import { createHash } from 'node:crypto';
import { signatureHash } from './algorithms.ts';
import { SignerError, UnsupportedError } from './errors.ts';
import type { SigningKey } from './signing-key.ts';

/** The part of @google-cloud/kms's KeyManagementServiceClient the backend uses. */
export interface KmsClient {
  asymmetricSign(request: {
    name: string;
    digest?: Record<string, Uint8Array>;
    data?: Uint8Array;
  }): Promise<[{ signature?: Uint8Array | string | null }, ...unknown[]]>;
}

// KMS signs a digest for RSA PKCS#1 and ECDSA keys, and the message itself for ML-DSA and SLH-DSA
const digests = new Set(['sha256', 'sha384', 'sha512']);

/** A KeyManagementServiceClient with Application Default Credentials. */
export async function createKmsClient(): Promise<KmsClient> {
  let kms: { KeyManagementServiceClient: new () => KmsClient };
  try {
    kms = await import('@google-cloud/kms');
  } catch {
    throw new UnsupportedError('load KMS client', '@google-cloud/kms is not installed');
  }
  return new kms.KeyManagementServiceClient();
}

/**
 * A SigningKey for a KMS CryptoKeyVersion (`projects/…/cryptoKeyVersions/N`), signing `algorithm`
 * (the CA certificate's). KMS checks it against the key's own algorithm; the caller verifies the
 * signature against `publicKey`, the CA certificate's.
 */
export function kmsKey(client: KmsClient, keyVersion: string, algorithm: string, publicKey: Uint8Array): SigningKey {
  const hash = signatureHash(algorithm);
  if (hash && !digests.has(hash)) throw new UnsupportedError('load CA key', `${algorithm} with KMS keys`);
  return {
    backend: 'kms',
    algorithm,
    publicKey: () => Promise.resolve(publicKey),
    async sign(tbs) {
      let signature: Uint8Array | string | null | undefined;
      try {
        [{ signature }] = await client.asymmetricSign(
          hash
            ? { name: keyVersion, digest: { [hash]: createHash(hash).update(tbs).digest() } }
            : { name: keyVersion, data: tbs },
        );
      } catch (err) {
        // gRPC errors name the status and the key, never credentials
        throw new SignerError('KMS asymmetricSign', err instanceof Error ? err.message : String(err));
      }
      if (!signature?.length) throw new SignerError('KMS asymmetricSign', 'no signature');
      return typeof signature === 'string' ? new Uint8Array(Buffer.from(signature, 'base64')) : signature;
    },
  };
}
