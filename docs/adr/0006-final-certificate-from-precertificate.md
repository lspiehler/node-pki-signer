# 0006. The final certificate is built from the CT precertificate

Date: 2026-11-15. Status: accepted.

## Context
A CA that embeds SCTs (RFC 6962) signs a precertificate with a critical poison extension (1.3.6.1.4.1.11129.2.4.3), submits it to CT logs, and puts their SCTs into the final certificate as the SignedCertificateTimestampList extension (1.3.6.1.4.1.11129.2.4.2). Each SCT signs the precertificate's TBS minus the poison, so the final certificate's TBS minus the SCT list must be the same bytes (RFC 6962 sections 3.1 and 3.2). Otherwise no browser can verify the SCTs.

PKIaaS.io signed the final certificate the way it signs any certificate: from the CSR again. Both `openssl ca -create_serial` and `caSignCSR` draw a new random serial and new dates for every signature, and the SCT list lands wherever the extension order puts it. The final certificate's SCTs never verified. This happens on every path: OpenSSL, native, and the IoT HSM agent.

## Decision
`signFinalCertificate({ precertificate, sctList, ca, key | pkcs11 | kms })` (and `Signer.signFinalCertificate`) builds the final certificate from the precertificate's own bytes (decided by the owner, 2026-11-15):

1. It checks that the CA issued the precertificate: the issuer is the CA's subject, and the CA's key verifies the signature. So the final certificate says nothing the CA's key hasn't already signed, provided `ca` is the caller's own copy of the CA certificate, never one that came with the request. An IoT HSM agent passes its stored certificate, so it can sign a final certificate safely, even one other agents signed the precertificate for. For a token or KMS key, the check that the key is the CA's runs after signing, as for `caSignCSR` (ADR 0003): a wrong key costs one signature, which is never returned.
2. It refuses a precertificate that isn't DER, doesn't have exactly one poison extension (critical, value NULL), or already has an SCT list.
3. It replaces the poison extension's bytes with the SCT list extension at the same index, in raw DER. The extension is not critical, and its extnValue is the caller's `sctList` bytes as they are. Only the lengths of the Extensions SEQUENCE, its `[3]` and the TBS change, written in their shortest form. Every other byte is copied, so an ASN.1 library never re-encodes the precertificate.
4. It signs the new TBS with the precertificate's signature algorithm, copying its AlgorithmIdentifier bytes. A backend (ADR 0003) signs it, and the signature is checked against the CA's key, as for `caSignCSR`.
5. Before returning, it checks the result independently of how it was built. The SCT list sits where the poison was, with exactly the given bytes. Both TBSs without their swapped extension are byte-equal. @peculiar re-encodes the certificate to the same bytes. OpenSSL reads it, and the CA's key verifies it.

There is no whole-operation OpenSSL fallback: OpenSSL's CLI can't build this certificate. An algorithm `forceOpenSSL` names is signed by the `openssl` or `openssl-pkcs11` backend instead. A Google KMS key that the `kms` backend can't sign (any but RSA SHA-256 today, or one forced to OpenSSL) is signed through its PKCS#11 module (libkmsp11) by `openssl-pkcs11`, as node-openssl-cert2 signs its precertificate. The result's `backend` says which backend signed; these aren't reported through `onFallback`, which is for whole operations that go to node-openssl-cert2. When no allowed backend can sign it, the result is an `UnsupportedError`, and the final certificate isn't issued. This includes RSA-PSS and Ed25519 precertificates (no PKIaaS.io CA signs with them) and ML-DSA or SLH-DSA on a PKCS#11 token.

## Consequences
- **pkiaas** calls it after the logs answer instead of signing the CSR again. It passes the precertificate's key source: the software key, or the OpenSSL backend alone when native signing is off. The serial and dates of the final certificate are the precertificate's.
- **The IoT HSM agent** gets a new sign type for it. Older agents can't sign final certificates, so pkiaas must not ask them to sign a precertificate either.
- **Tests** cover every CA key type PKIaaS.io offers, each backend, the poison first, in the middle and last, every length boundary at 128, 256 and 65536, and each refusal. `openssl verify` and `openssl x509 -text` check each final certificate. CT logs and SCT signature verification are tested in pkiaas.
