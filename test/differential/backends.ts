// The CA key types each key backend is checked with in backends.test.ts, which its allowlist entries
// must match (src/allowlist.test.ts).
import { caKeySpecs, type KeySpec } from './fixtures.ts';

const classical = caKeySpecs.filter((spec) => !spec.pqc);

export const backendSpecs: Record<string, KeySpec[]> = {
  // openssl dgst with the PEM key: every key type node:crypto signs too
  openssl: caKeySpecs,
  // SoftHSM 2.6 has no ML-DSA or SLH-DSA
  pkcs11: classical,
  'openssl-pkcs11': classical,
};
