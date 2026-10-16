/**
 * Where a private key lives and how to sign with it. Building a certificate, CRL or CSR only needs
 * the issuer's public key and a signature over the to-be-signed bytes, so every key custody
 * (software key, PKCS#11 token, Google Cloud KMS, OpenSSL fallback) is one implementation of this.
 */
export interface SigningKey {
  /** The signature algorithm this key produces, e.g. 'sha256WithRSAEncryption', 'ecdsa-with-SHA384', 'ML-DSA-65'. */
  readonly algorithm: string;

  /** The public key as DER-encoded SubjectPublicKeyInfo. */
  publicKey(): Promise<Uint8Array>;

  /** Signs the DER-encoded to-be-signed structure and returns the signature value as it goes in the BIT STRING. */
  sign(tbs: Uint8Array): Promise<Uint8Array>;
}
