# node-pki-signer

Fast, in-process X.509 signing for [PKIaaS.io](https://pkiaas.io) and the [IoT HSM](https://github.com/lspiehler/iot-hsm) agent.

It signs certificates with software keys, PKCS#11 tokens (YubiKey, SoftHSM) and Google Cloud KMS, including post-quantum keys (ML-DSA, SLH-DSA). Anything it can't do natively falls back to OpenSSL, so new algorithms work as soon as OpenSSL supports them.

Status: early development (0.x): the API may still change. PKIaaS.io runs it in shadow mode (ADR 0004) before it signs there.

## Usage

`createSigner` is a drop-in for node-openssl-cert2's `x509.CASignCSR`: same parameters, same callback. It signs natively when the CA's signature algorithm is on the allowlist for a backend that can reach the key (`src/allowlist.ts`, ADR 0003) and hands the whole request to node-openssl-cert2 otherwise:

| Key | Backends, preferred first | Allowlisted |
|---|---|---|
| `key` (PEM) | node:crypto, then `openssl dgst` | every CA key type and hash |
| `pkcs11: { uri, pin, modulePath }` | pkcs11js, then `openssl dgst` with pkcs11-provider | RSA and ECDSA |
| `kms: { keyVersion }` | the Google Cloud KMS API | RSA with SHA-256 (tested against a real KMS key) |

Non-software signatures are verified against the CA certificate before the certificate is returned. pkcs11js and @google-cloud/kms are optional peer dependencies, loaded only when needed: install them beside this package to sign with PKCS#11 tokens (`npm install pkcs11js`) or Google Cloud KMS (`npm install @google-cloud/kms`). Without them, those keys go to OpenSSL.

```js
const { createSigner } = require('node-pki-signer');

const signer = createSigner({
  // optional: the openssl binary for the fallback
  binpath: '/usr/bin/openssl',
  // optional: algorithms that always go to OpenSSL, or true for all of them
  forceOpenSSL: ['ML-DSA-65'],
  // optional: the backends that may sign natively; all by default
  backends: ['software', 'openssl', 'pkcs11', 'openssl-pkcs11', 'kms'],
  // every fallback with its reason; a console.warn by default
  onFallback: (fallback) => log.logEvent(`${fallback.operation} fell back to OpenSSL: ${fallback.reason}`),
});

signer.x509.CASignCSR({ csr, options, ca, key, password }, (err, crt) => {
  // crt.data is the certificate; crt.signedBy is 'native' or 'openssl'
});
// or: const { data, serial, signedBy } = await signer.caSignCSR({ csr, options, ca, key, password });
```

What falls back:

- **Not supported natively** (`UnsupportedError`): hashes and key types outside the allowlist, libkmsp11 keys without `kms.keyVersion`, a missing pkcs11js or @google-cloud/kms, a CA certificate the library can't re-encode exactly, and values its ASN.1 libraries can't encode (see `docs/upstream-issues.md`, dates before 1950, lone surrogates, and a `pathlen` that isn't a safe integer).
- **Forced** by `forceOpenSSL`.
- **Unexpected errors** in the native path, so a bug there doesn't stop issuance.

A refusal of the request itself (`SignerError`: wrong passphrase or PIN, a token or KMS key that isn't the CA's, a CSR whose signature doesn't verify, a subject OpenSSL would refuse) doesn't fall back, because OpenSSL refuses it too. Fallback reasons never contain keys, passphrases, PINs or CSRs. Requests that fall back get node-openssl-cert2's old subject and date behaviour (ADR 0002).
