# 0004. Shadow mode without signing

Date: 2026-10-17. Status: accepted.

## Context
ADR 0001 says the native signer runs in production in shadow mode before it replaces `openssl ca`. The differential harness covers the input shapes we know of. Shadow mode checks the requests that production actually gets. Signing every request a second time would cost a Google Cloud KMS signature each time (billed). It would also use a YubiKey a second time, and the platform can't do it at all for keys that live on an IoT HSM agent.

## Decision
`shadowCASignCSR(params, certificate)` builds the TBS the native signer would build for `params` and compares it byte for byte with the TBS of `certificate`, the certificate that was actually issued. It doesn't sign:
- **Serial and dates:** the serial number comes from the issued certificate. So does the validity when the options have no `startdate`, since `days` counts from the moment of signing. Otherwise the validity is built from the options and compared like any other field.
- **No key:** only the CSR, the options and the CA certificate are needed, so the platform can check certificates that agents sign. The signature algorithm comes from the CA certificate and `options.hash`, as it does when signing.
- **Result:** `match`; `differ` with the names of the TBS fields that differ (`subject`, `validity`, `extension 2.5.29.17`, …), never their values; `unsupported` (the request would go to OpenSSL); or `refused` (the native signer would refuse it), each with its step and reason. It never throws, so a caller can't break issuance with it.
- **What it doesn't check:** the allowlist and the backends. Which backend would sign doesn't change the TBS. The live and differential tests cover the signatures.

## Consequences
- The differential harness also runs shadow mode against every reference certificate. All of them match, except the intended subject differences of ADR 0002, which show up as `subject`.
- Intended differences (ADR 0002) show up as `differ` in production too, so callers should expect `subject` differences where the reference cuts the subject short.
- `buildTBS`, `validity` and `parseRequest` are split out of `caSignCSR` so that both paths build the TBS with the same code. `test/differential/compare.ts` uses the library's TBS field splitter (`src/tbs-fields.ts`).
