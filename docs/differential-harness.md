# Differential harness

Phase 0 of ADR 0001. The harness proves that a new signing path issues the same certificates as today's: node-openssl-cert2 `x509.CASignCSR` 0.7.37, which pkiaas master runs. It signs every corpus case with both paths and compares the results. The candidate is the library's native signer, `caSignCSR` (phase 1).

Run it with `npm test`, or only the harness with `node --test test/differential/differential.test.ts` (about 15 seconds). It needs the system `openssl` 3.5 or later, because the reference path calls it.

## What it compares
For each case, with the validity dates fixed by the options:
- **Each TBS field, byte for byte:** version, signature algorithm, issuer, validity, subject, public key, every extension by OID, and the extension order. `signatureAlgorithm` must also equal the TBS `signature` field.
- **Serial number:** both paths draw it at random (`openssl ca -create_serial`), so it's checked for form only: positive, at most 20 octets, minimally encoded (RFC 5280 4.1.2.2).
- **Signature value:** not compared, because ECDSA and ML-DSA signatures are randomized. Both certificates must pass `openssl verify` against the issuing CA instead. CT precertificates are verified with `-ignore_critical` because of the poison extension.
- **`openssl x509 -text`:** the same, apart from the serial number and signature value.
- **Refusals:** if the reference refuses a case, the candidate must refuse it too (`referenceRejects`).
- **Fallbacks:** for the cases in `fallsBack`, the native signer throws `UnsupportedError`, so `createSigner` falls back to OpenSSL and issues the reference's certificate. Shadow mode must report them as `unsupported`.
- **Intended differences (ADR 0002):** for the cases in `fullSubjects`, the reference truncates, empties or refuses the subject. The candidate must issue the full subject listed there, and nothing else may differ.
- **CSR versions (ADR 0005):** for the cases in `csrVersions`, CSRs with version 2 instead of v1, the reference refuses and the candidate must sign: with the CSR's key, verified by `openssl verify`, and matched by shadow mode.

In phase 0 the candidate was the reference itself, which showed that the corpus and the comparison are deterministic. The harness's own tests check that it reports a missing extension, a changed validity and a refusal.

## Key backends (`test/differential/backends.test.ts`, ADR 0003)
Every CA key type and hash a backend supports (`backends.ts`, which the allowlist must match) is signed with that backend alone and compared the same way:
- **`openssl`:** the PEM key through `openssl dgst`, against the usual reference.
- **`pkcs11` and `openssl-pkcs11`:** the CA key is imported into a SoftHSM token (`softhsm.ts`). The reference gets the agent's parameters (`pkcs11` and `options.module`) and runs `openssl ca` through pkcs11-provider. That crashes unloading SoftHSM after writing the certificate, so the reference accepts a certificate written before a SIGSEGV. Also checked: a wrong PIN is refused without the PIN in the message, the right PIN logs in again, and a token key that isn't the CA's fails verification. Needs `softhsm2` and `pkcs11-provider`; skipped without them unless `CI` is set.
- **`kms`:** a stand-in for `asymmetricSign` (`fake-kms.ts`) that holds the CA key and refuses what KMS refuses. It covers the key types and digests KMS offers (RSA with SHA-256/512, P-256 with SHA-256, P-384 with SHA-384, ML-DSA, SLH-DSA-SHA2-128s), bypassing the allowlist. KMS algorithms are allowlisted only after `test/live/kms.test.ts` passes against the real service with a key of that kind: it runs when `LIVE_KMS_KEY_VERSION` names a key version (Application Default Credentials, libkmsp11 for the reference), issues hour-long certificates from a throwaway issuer certificate under a test name, so even a production CA's key can be used, and stops after 12 KMS signatures because each one is billed.

The native signer's own tests (`src/ca-sign-csr.test.ts`) cover what the harness can't: dates in a time zone that isn't UTC, `days` without a `startdate`, and each refusal naming its step.

`test/live/pkcs11.test.ts` runs both PKCS#11 backends against a real token, e.g. a YubiKey, when `LIVE_PKCS11_URI` names a private key (with `LIVE_PKCS11_MODULE`, libykcs11 by default, and the user PIN in `LIVE_PKCS11_PIN`; never a wrong one, since a YubiKey blocks after three). It signs every hash against the same reference. The reference runs first in its own process, which also checks that pkcs11js logs in again after another process used the token. Certificates come from a throwaway issuer certificate under a test name (`test/live/issuer.ts`) and are valid for an hour, so even a production CA's key can be used.

## Corpus (`test/differential/corpus.ts`)
Options are built the way pkiaas builds them: the CSR goes through node-openssl-cert2's `csr.parse`, then through a copy of pkiaas's `processOptions` (`pkiaas-options.ts`, from `lib/template/processTemplate.js`). Keys, CAs and CSRs are generated on each run.
- **Templates:** every template shape (`test/corpus/templates.json`), on an RSA-2048 CA. That's the 4 presets plus the 83 other distinct `options` of the 626 templates on dev, with subject values and custom AIA URLs anonymized. A read-only scan of the 7532 production templates (2026-10-18, shapes only, no values) added the cases named `template with …` and `template policy OID …`: very long validities, unusual `hash` spellings, IPsec and Microsoft EKU names, an unknown EKU name, `encipherOnly`/`decipherOnly`, non-critical basic constraints, custom AIA URLs that are empty, not URLs, or padded with a tab and spaces, and a template `policy_oid` that is NULL (a fifth of them), empty or anyPolicy. Production has no nested subject arrays; its other subject shapes are covered by the admin override cases.
- **CA key types:** all 20 that pkiaas offers. RSA and EC are each run with sha1/224/256/384/512; ML-DSA and SLH-DSA with `default` (what service certificates use) and `sha256` (what the preset templates carry).
- **CSRs** shaped like those from:
  - ACME (empty subject)
  - Intune SCEP (UPN otherName, challengePassword)
  - MS CES (template extension, with pkiaas's leading-space OID)
- **Other CSR and subject cases:**
  - UTF-8 and punctuation in subjects
  - multi-valued and less common attributes
  - every SAN type
  - every subject key type, Ed25519 included
  - must-staple (the TLS feature extension, which `csr.parse` passes through)
- **Other signing paths:**
  - admin overrides, including awkward subject values and every subject attribute
  - options without a subject, which keep the CSR's subject
  - the legacy `/admin` sign path (`lib/admin/ca/signcert.js`)
  - CT precertificates and final certificates with an SCT list
  - OCSP, timestamping and SCEP RA service certificates

## What the reference does today
The native signer reproduces these. The intended differences are in ADR 0002.
- **Extension order:**
  - Subject Key Identifier and Authority Key Identifier (key ID only) come first.
  - The rest follow the key order of `options.extensions`. `customOIDs` (template OID, CT poison, SCT list) sit wherever that key is.
  - Subject Alternative Name always comes last.
- **String types:** `-utf8` with the default `string_mask`, so country, serialNumber and dnQualifier are PrintableString, emailAddress and domainComponent are IA5String, and everything else is UTF8String.
- **Subject:** forced from `options.subject` when the options have one. If they don't, the CSR's subject is kept. The CSR's extensions are never copied.
- **Subject order:** the order of node-openssl-cert2's `signing_policy` (C, ST, L, postalCode, street, O, OU, CN, emailAddress, …), not the order given. Its config sets `preserve = yes`, but `openssl ca` still applies the policy order. Phase 0 missed this because its candidate was the reference.
- **PQC digest:** with ML-DSA and SLH-DSA CAs, `sha256` gives the same certificate as `default`. OpenSSL ignores the digest.
- **Empty usages:** SCEP RA certificates with empty key usage and extended key usage lists get neither extension.
- **Custom AIA URLs:** `"a, b"` gives two URIs, with the space trimmed.
- **MS CES template OID:** the leading-space form (`' 1.3.6.1.4.1.311.21.7'`) is accepted.
- **Refused values (0.7.37):** a control character anywhere in the subject or extensions, and a `hash` with anything but letters, digits, `_` and `-` (so `'sha256 '`). `$`, `#`, quotes and backslashes are escaped in `openssl.cnf`, so they come out literally instead of expanding `$ENV::NAME` or cutting the value.

## Quirks found
Quirks 1, 3 and 4 are fixed in the native signer (ADR 0002). Quirk 2 is pkiaas's to fix.
1. **Subjects are silently truncated.** `getDistinguishedName` builds `-subj` escaping only spaces. A `/` or `+` in a subject value cuts the subject at that point, and every later attribute is lost, including the common name. For example, `O=Ops/Infra, CN=host` is issued as `O=Ops`. A backslash disappears. Values can reach `-subj` from templates, admin overrides or CSRs.
2. **`csr.parse` mangles subjects, and the result depends on attribute order.** `CN=a, b` becomes `a`. `O=Ops/Infra` becomes `Ops, Infra`. Quotes are stripped. A CSR with `=` in a value is refused (`Invalid subject: undefined`), and so is one with an escaped `+` (the `-subj` problem above). This happens in pkiaas before signing, so it's outside this library, but it shapes what the library is given.
3. **Validity dates depend on the host's time zone.** `CASignCSR` formats `-startdate`/`-enddate` in local time and appends `Z`. On a host that isn't on UTC, `notBefore` and `notAfter` shift by the UTC offset: in Asia/Tokyo, certificates aren't valid until 9 hours after issue. pkiaas containers and both IoT HSM installs (the Docker image's `TZ=UTC`, and `setup_ubuntu.sh`'s `timedatectl set-timezone UTC`) run on UTC, so only agents whose time zone was changed are affected. The harness pins `TZ=UTC`.
4. **Nested subject arrays empty the subject.** The pkiaas template editor can save `countryName: [["US"]]` (10 of the 87 template shapes on dev). `getDistinguishedName` throws on it and falls back to `-subj /`, or keeps only the attributes before the nested one. Certificates from these templates have an empty or partial subject, without the CSR's common name.
