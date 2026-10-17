# node-pki-signer

Fast, in-process X.509 signing for [PKIaaS.io](https://pkiaas.io) and the [IoT HSM](https://github.com/lspiehler/iot-hsm) agent.

It signs certificates with software keys, PKCS#11 tokens (YubiKey, SoftHSM) and Google Cloud KMS, including post-quantum keys (ML-DSA, SLH-DSA). Anything it can't do natively falls back to OpenSSL, so new algorithms work as soon as OpenSSL supports them.

Status: early development, not yet published.

## Usage

`createSigner` is a drop-in for node-openssl-cert2's `x509.CASignCSR`: same parameters, same callback. It signs natively when the CA's signature algorithm is on the allowlist (`src/allowlist.ts`: software keys with every algorithm the differential harness covers) and hands the whole request to node-openssl-cert2 otherwise.

```js
const { createSigner } = require('node-pki-signer');

const signer = createSigner({
  // optional: the openssl binary for the fallback
  binpath: '/usr/bin/openssl',
  // optional: algorithms that always go to OpenSSL, or true for all of them
  forceOpenSSL: ['ML-DSA-65'],
  // every fallback with its reason; a console.warn by default
  onFallback: (fallback) => log.logEvent(`${fallback.operation} fell back to OpenSSL: ${fallback.reason}`),
});

signer.x509.CASignCSR({ csr, options, ca, key, password }, (err, crt) => {
  // crt.data is the certificate; crt.signedBy is 'native' or 'openssl'
});
// or: const { data, serial, signedBy } = await signer.caSignCSR({ csr, options, ca, key, password });
```

What falls back:

- **Not supported natively** (`UnsupportedError`): PKCS#11 keys, hashes and key types outside the allowlist, a CA certificate the library can't re-encode exactly.
- **Forced** by `forceOpenSSL`.
- **Unexpected errors** in the native path, so a bug there doesn't stop issuance.

A refusal of the request itself (`SignerError`: wrong passphrase, a CSR whose signature doesn't verify, a subject OpenSSL would refuse) doesn't fall back, because OpenSSL refuses it too. Fallback reasons never contain keys, passphrases, PINs or CSRs. Requests that fall back get node-openssl-cert2's old subject and date behaviour (ADR 0002).
