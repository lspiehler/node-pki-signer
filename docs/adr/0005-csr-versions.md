# 0005. CSRs with a version other than v1

Date: 2026-10-17. Status: accepted.

## Context
RFC 2986 says a CSR's `version` shall be 0 (v1). Some clients write 2 instead: a Meraki mobile device management product, and the SCEP request of another CA. Both examples are in OpenSSL issue [28761](https://github.com/openssl/openssl/issues/28761).

OpenSSL 3.3.5 signs these CSRs, and Microsoft's CA does. OpenSSL 3.5 doesn't: `X509_REQ_verify` refuses any version but v1 ("unsupported version", the check from [PR 24677](https://github.com/openssl/openssl/pull/24677)), so `openssl ca` refuses them, and so does `openssl req -verify`. There is no option to skip the check, and OpenSSL said it won't change. node-openssl-cert2's `CASignCSR`, the reference of ADR 0001, refuses them for this reason, not because of anything else in the request.

The version isn't copied into the certificate, and a certificate's own version is always v3. The CSR's signature verifies over its bytes as sent, version included.

## Decision
The native signer accepts CSRs whatever their `version` (decided by the owner, 2026-10-17). It still verifies the CSR's signature over the bytes as sent and refuses one that doesn't verify. Nothing else changes: the certificate is the one `openssl ca` would have issued for the same request with version 0.

## Consequences
- **The harness** signs both CSRs from the OpenSSL issue (`test/corpus/csr-version-2-*.pem`, cases in `csrVersions` in `test/differential/differential.test.ts`). The reference refuses them. The candidate must sign them with the CSR's key, `openssl verify` must accept the certificate, and shadow mode must match it.
- **Shadow mode** in production never sees these CSRs while `openssl ca` signs: OpenSSL refuses them, so no certificate is issued to compare with.
- **pkiaas still refuses them before signing:** `lib/template/processTemplate.js` parses the CSR with `openssl req -verify` (`parseCSR({ verify: true })`). They're issued only once pkiaas checks the CSR's signature without OpenSSL, for example with this library, and signs natively. That's a separate pkiaas change. Until then the corpus parses them without `-verify`, as pkiaas's other CSR parsing does.
- **The OpenSSL fallback** (node-openssl-cert2) still refuses them. A request that falls back is refused as before.
