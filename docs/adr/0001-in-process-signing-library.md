# 0001. In-process signing library with OpenSSL fallback

Date: 2026-10-16. Status: accepted.

## Context
PKIaaS.io and the IoT HSM agent sign by starting one `openssl` process per signature through node-openssl-cert2 (`openssl ca`, `cms -sign`, `ca -gencrl`). On the agent, each Google Cloud KMS signature also loads libkmsp11: measured on 2026-10-16, module load and login take 1.56 s of a 1.77 s signature, and the KMS sign itself about 0.2 s. libkmsp11 also segfaults intermittently (GoogleCloudPlatform/kms-integrations#62), supports no post-quantum keys, and ships for amd64 only. The platform starts about 22 processes per enrollment.

Requirements: every key type the platform offers (RSA 2048/4096, EC P-256/384/521, ML-DSA-44/65/87, all 12 SLH-DSA sets) and hashes (SHA-1/256/384/512); software keys, YubiKey, SoftHSM and Google KMS through its API, with room for more; runs on the platform (Docker swarm) and the agent (Docker, Linux x86_64 and ARM, a future appliance image, maybe Windows); input and output close to today's so callers barely change; certificates first, later CRL, CSR, OCSP and CMS; must never wait on this library for new post-quantum algorithms; stateless apart from KMS and PKCS#11 connections.

## Decision
A TypeScript library that both apps load and call in-process:
- **Software keys:** `node:crypto`, which is OpenSSL 3.5 bundled with Node (ML-DSA since Node 24.6, SLH-DSA since 24.8).
- **Structures:** the to-be-signed structure is built with `@peculiar/asn1-*` and signed through a `SigningKey` (`publicKey()`, `sign(tbs)`).
- **Google KMS:** `@google-cloud/kms` `asymmetricSign`, with one long-lived client per credential.
- **PKCS#11:** `pkcs11js` with long-lived sessions.
- **OpenSSL fallback, two levels:**
  1. An OpenSSL backend signs the library's to-be-signed bytes with the system `openssl pkeyutl -sign -rawin`.
  2. Anything the library can't build yet goes to node-openssl-cert2 unchanged.

  Only allowlisted algorithm × backend pairs that passed the differential tests run natively.
- **Interface:** the first function is a drop-in replacement for node-openssl-cert2's `x509.CASignCSR`: same options object, same PEM output.
- **Protocol:** the platform ↔ agent protocol does not change, so old and new agents interoperate.

## Alternatives rejected
- **Go:** `crypto/x509` can't sign SLH-DSA and isn't extensible; its OCSP and PKCS#7 libraries lack ML-DSA.
- **Pure Rust:** RustCrypto's ML-DSA and SLH-DSA crates are pre-1.0 and unaudited, and it would add a fourth language and per-platform binaries. A Rust helper on the `openssl` crate, kept running and talking over stdio, remains the fallback design if Node's PQC or `pkcs11js` disappoints.
- **A separate signing service (sidecar or swarm service with mTLS):** software CA keys would cross the network on every signature, or the service would need the database and the encryption key. It adds certificate management and a network hop, and gives no speed-up: the cost was process start-up, not where the signing runs.
- **The sign-server engine (Rust, HTTP):** too broad, its key backends were unimplemented, and its certificate override model differs from today's.
- **Keeping libkmsp11 behind a long-lived OpenSSL helper:** this would fix start-up only. It still segfaults, still has no PQC, and is still amd64-only.

## Consequences
- **Proving equivalence:** a differential harness signs a corpus (every template × key type × hash, plus real CSRs from SCEP/Intune, MS CES, ACME, CT and service certs) both ways and compares the DER. Then shadow mode in production before switching.
- **Hosts:** the agent and platform images need Node ≥ 24.8 (24.11 or later in practice) and, for the fallback, a system OpenSSL ≥ 3.5.
- **YubiKey lock:** a long-lived PKCS#11 session holds the YubiKey, so the agent's key generation and import must pause it or go through the library.
- **Distribution:** the repo is private, while iot-hsm is public and installed by customers. How the agent gets this package (private registry, bundling, or making it public) must be decided before the agent uses it.
