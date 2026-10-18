# 0003. Key backends: PKCS#11, Google Cloud KMS and OpenSSL

Date: 2026-10-17. Status: accepted.

## Context
ADR 0001 plans one `SigningKey` per key custody and a first fallback level in which the system OpenSSL signs the library's to-be-signed bytes. Phases 1 and 2 signed only software keys (PEM, node:crypto). The IoT HSM agent passes its keys to node-openssl-cert2 as `params.pkcs11 = { uri, pin, modulePath }`: YubiKey (libykcs11), SoftHSM and Google Cloud KMS through libkmsp11. Its URIs name the token by `serial` and the key by `id` (or `object`, the CryptoKey ID, for libkmsp11), and it sets `options.module` for node-openssl-cert2's config. Each signature starts `openssl ca`, which loads the module and logs in: about 100 ms with SoftHSM (measured 2026-10-17) and 1.6 s with libkmsp11.

Found while building this: `openssl ca` with pkcs11-provider 1.2 and SoftHSM 2.6 writes the certificate and then crashes (SIGSEGV) unloading the module at exit; the provider's `pkcs11-module-quirks = no-deinit` avoids it. SoftHSM and libkmsp11 both use OpenSSL themselves, so this is likely the same crash the agent retries for libkmsp11 (GoogleCloudPlatform/kms-integrations#62). `openssl dgst` crashes the same way, though less often. Also, when several processes use one SoftHSM token at once, some of them don't find its keys: 7 of 72 signatures with 24 concurrent `openssl dgst` processes. The agent signs SoftHSM requests in parallel `openssl` processes today.

## Decision
**Backends.** `caSignCSR` picks the key from the parameters, in this order of preference, and uses the first backend whose algorithm is allowlisted:

| Parameters | Backends, preferred first |
|---|---|
| `kms: { keyVersion }` | `kms`: the KMS API's `asymmetricSign` (`@google-cloud/kms`), one client per process with Application Default Credentials |
| `pkcs11` (not libkmsp11) | `pkcs11`: pkcs11js; then `openssl-pkcs11`: `openssl dgst -sign <uri>` with pkcs11-provider |
| `key` (PEM) | `software`: node:crypto; then `openssl`: `openssl dgst -sign` |

When no backend is allowlisted, or none can load (e.g. pkcs11js isn't installed), the whole operation falls back to node-openssl-cert2 as before. `backends` limits which may sign, e.g. `['openssl-pkcs11']` to keep pkcs11js's long-lived login off a YubiKey.

- **The algorithm comes from the CA certificate** (its public key type and `options.hash`), so building the TBS never asks the token or KMS anything.
- **Every signature from a non-software backend is verified** against the CA certificate's public key before the certificate is returned. A token, KMS or openssl signs with a key the library never sees, so this is the only check that the key is the CA's. KMS's CRC32C checksums are therefore not used.
- **pkcs11js:** each module is loaded once, and each token keeps one logged-in session. Every signature opens its own session (which shares the login), finds the key by the URI's `id`/`object`, and signs with `CKM_RSA_PKCS` over a DigestInfo or `CKM_ECDSA` over the digest. The hash is computed in Node, so tokens only need the most widely supported mechanisms. A different PIN logs out and logs in again (the PIN is kept only as a SHA-256 hash). `Signer.close()` logs out and unloads the modules. Only RSA and ECDSA for now: SoftHSM 2.6 has no ML-DSA or SLH-DSA to test against.
- **Google KMS:** libkmsp11's URI names the CryptoKey, not the version, so the agent passes `kms: { keyVersion: 'projects/…/cryptoKeyVersions/N' }` beside `pkcs11`. The native path uses the API; the fallback keeps using libkmsp11. Without `kms`, a libkmsp11 key falls back. KMS gets a digest for RSA PKCS#1 and ECDSA keys and the message for ML-DSA and SLH-DSA; it refuses a digest that isn't the key's, and that refusal is passed on.
- **OpenSSL:** `openssl dgst -sign`, not `pkeyutl -sign -rawin` as ADR 0001 said: `pkeyutl` can't sign ML-DSA or SLH-DSA input from a pipe ("unable to determine file size for oneshot operation"). openssl can't open the socket Node passes as a child's extra stdio, so a PEM key goes through a pipe that bash opens (`-sign <(cat <&4)`), and the passphrase or PIN through `-passin fd:3`. Nothing goes to a file or an argument. For PKCS#11 keys, `PKCS11_PROVIDER_MODULE` names the module. A SIGSEGV after a full signature counts as success because of the exit-time crash above; the verification catches anything else.
- **Errors:** a wrong PIN, a key that isn't the CA's and KMS refusals are refusals (`SignerError`): they don't fall back, so a wrong PIN is never tried twice against a YubiKey's retry counter. A module pkcs11js can't load and a mechanism the token refuses are `UnsupportedError`.

**Allowlist (phase 3):**
- `openssl`: every CA key type and hash, like `software`.
- `pkcs11` and `openssl-pkcs11`: RSA and ECDSA with SHA-1/256/384/512, tested on SoftHSM.
- `kms`: nothing yet. The harness checks the requests and signatures against a stand-in client, not Google's service; KMS is allowlisted after a test against a real key.
- **Update 2026-10-17:** `kms` allowlists `sha256WithRSAEncryption`, the only algorithm tested against Google's service so far (`test/live/kms.test.ts` with an HSM `RSA_SIGN_PKCS1_2048_SHA256` key: same TBS and text as libkmsp11, KMS refusals passed on, a wrong CA key caught, about 110 ms per certificate against about 1.8 s). Other KMS algorithms stay off the allowlist until the live test passes with a key of that kind.

**Dependencies:** pkcs11js 2.1.7 and @google-cloud/kms 6.2.1 are optional dependencies, loaded only when a key needs them. pkcs11js compiles at install (node-gyp: python3, make, a C++ compiler); if it can't, PKCS#11 keys go to OpenSSL. **Update 2026-10-17 (0.3.0):** both are optional *peer* dependencies instead, so npm installs them only where the application asks for them. PKIaaS.io, which signs only software keys natively, installs neither: the KMS client brought about 45 packages, some newer than the 14-day rule allows, plus pkcs11js's failed native build in an image without a compiler. The IoT HSM agent lists them in its own dependencies.

## Consequences
- **Speed:** on SoftHSM, a certificate takes about 4 ms with pkcs11js against about 100 ms through `openssl ca` (`openssl dgst` with pkcs11-provider: also about 100 ms, the module load).
- **The harness** (`test/differential/backends.test.ts`) signs every CA key type and hash a backend supports with that backend and compares it with node-openssl-cert2 signing with the same key. For PKCS#11, the key is imported into a SoftHSM token and the reference runs `openssl ca` through pkcs11-provider as the agent does; its exit-time crash is ignored when the certificate was written. Those cases run one at a time, reference first, because of the multi-process race above; pkcs11js, a single process, doesn't have it. CI installs SoftHSM and pkcs11-provider; elsewhere those tests are skipped unless `CI` is set.
- **Before the agent uses it:** a check on a real YubiKey (libykcs11), including whether the long-lived login blocks the agent's key generation and import (ADR 0001); the KMS test against a real key; and the agent passing `kms.keyVersion`.
- **YubiKey check (2026-10-17, YubiKey 5.2.4 with libykcs11 2.7.1 on the IoT HSM test device, beside the running agent):** pkcs11js's long-lived login doesn't block anything the agent does in other processes: `openssl ca` signing, key generation with `pkcs11-tool --keypairgen` and import with `yubico-piv-tool -aimport-key` all succeeded while it was logged in. But any other process using the YubiKey resets its PIV login, after which libykcs11 hides the private keys from this process (`find PKCS#11 key: no private key matches`) until it logs in again. So a signature that finds no key, or gets `CKR_USER_NOT_LOGGED_IN`, logs in again and is retried once. A wrong PIN still isn't retried, because a login that fails is refused before signing. Keys generated or imported meanwhile are found after that login. A certificate takes about 80 ms (P-256) or 145 ms (RSA-2048), against about 3.4 s through `openssl ca`; the first after another process used the token takes about 1.8 s because of the new login. `test/live/pkcs11.test.ts` passes for both PKCS#11 backends with every hash on a generated RSA key, an imported P-256 key and a P-256 key generated earlier.
- **Not covered:** PKCS#11 ML-DSA and SLH-DSA (PKCS#11 3.2 mechanisms), RSA-PSS and Ed25519 keys; they fall back.

## Update 2026-10-18: SHA-224
The platform's template editor offers SHA-224 (the `hash_algorithms` table), so RSA and ECDSA with SHA-224 joined the corpus and the allowlists of `software`, `openssl`, `pkcs11` and `openssl-pkcs11` after passing the differential tests, on SoftHSM for the token backends. Google Cloud KMS has no SHA-224 keys, so those requests still go to OpenSSL.
