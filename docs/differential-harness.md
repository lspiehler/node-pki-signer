# Differential harness

Phase 0 of ADR 0001. The harness proves that a new signing path issues the same certificates as today's: node-openssl-cert2 `x509.CASignCSR` 0.7.34, which pkiaas master runs. It signs every corpus case with both paths and compares the results.

Run it with `npm test`, or only the harness with `node --test test/differential/differential.test.ts` (about 15 seconds). It needs the system `openssl` 3.5 or later, because the reference path calls it.

## What it compares
For each case, with the validity dates fixed by the options:
- **Each TBS field, byte for byte:** version, signature algorithm, issuer, validity, subject, public key, every extension by OID, and the extension order. `signatureAlgorithm` must also equal the TBS `signature` field.
- **Serial number:** both paths draw it at random (`openssl ca -create_serial`), so it's checked for form only: positive, at most 20 octets, minimally encoded (RFC 5280 4.1.2.2).
- **Signature value:** not compared, because ECDSA and ML-DSA signatures are randomized. Both certificates must pass `openssl verify` against the issuing CA instead. CT precertificates are verified with `-ignore_critical` because of the poison extension.
- **`openssl x509 -text`:** the same, apart from the serial number and signature value.
- **Refusals:** if the reference refuses a case, the candidate must refuse it too (`referenceRejects`).

Until the native path exists, the candidate is the reference itself. That shows the corpus and the comparison are deterministic. The harness's own tests check that it reports a missing extension, a changed validity and a refusal.

## Corpus (`test/differential/corpus.ts`)
Options are built the way pkiaas builds them: the CSR goes through node-openssl-cert2's `csr.parse`, then through a copy of pkiaas's `processOptions` (`pkiaas-options.ts`, from `lib/template/processTemplate.js`). Keys, CAs and CSRs are generated on each run.
- **Templates:** every template shape (`test/corpus/templates.json`), on an RSA-2048 CA. That's the 4 presets plus the 83 other distinct `options` of the 626 templates on dev, with subject values and custom AIA URLs anonymized.
- **CA key types:** all 20 that pkiaas offers. RSA and EC are each run with sha1/256/384/512; ML-DSA and SLH-DSA with `default` (what service certificates use) and `sha256` (what the preset templates carry).
- **CSRs** shaped like those from:
  - ACME (empty subject)
  - Intune SCEP (UPN otherName, challengePassword)
  - MS CES (template extension, with pkiaas's leading-space OID)
- **Other CSR and subject cases:**
  - UTF-8 and punctuation in subjects
  - multi-valued and less common attributes
  - every SAN type
  - every subject key type, Ed25519 included
- **Other signing paths:**
  - admin overrides, including awkward subject values
  - the legacy `/admin` sign path (`lib/admin/ca/signcert.js`)
  - CT precertificates and final certificates with an SCT list
  - OCSP, timestamping and SCEP RA service certificates

## What the reference does today
Phase 1 must reproduce these, or an ADR must record the intended difference:
- **Extension order:**
  - Subject Key Identifier and Authority Key Identifier (key ID only) come first.
  - The rest follow the key order of `options.extensions`. `customOIDs` (template OID, CT poison, SCT list) sit wherever that key is.
  - Subject Alternative Name always comes last.
- **String types:** `-utf8` with the default `string_mask`, so country is PrintableString, emailAddress and domainComponent are IA5String, and everything else is UTF8String. The subject is always forced from `options.subject`, in that order (`preserve = yes`). The CSR's own subject and extensions are never copied.
- **PQC digest:** with ML-DSA and SLH-DSA CAs, `sha256` gives the same certificate as `default`. OpenSSL ignores the digest.
- **Empty usages:** SCEP RA certificates with empty key usage and extended key usage lists get neither extension.
- **Custom AIA URLs:** `"a, b"` gives two URIs, with the space trimmed.
- **MS CES template OID:** the leading-space form (`' 1.3.6.1.4.1.311.21.7'`) is accepted.

## Quirks found
These are flagged, not decided:
1. **Subjects are silently truncated.** `getDistinguishedName` builds `-subj` escaping only spaces. A `/` or `+` in a subject value cuts the subject at that point, and every later attribute is lost, including the common name. For example, `O=Ops/Infra, CN=host` is issued as `O=Ops`. A backslash disappears. Values can reach `-subj` from templates, admin overrides or CSRs.
2. **`csr.parse` mangles subjects, and the result depends on attribute order.** `CN=a, b` becomes `a`. `O=Ops/Infra` becomes `Ops, Infra`. Quotes are stripped. A CSR with `=` in a value is refused (`Invalid subject: undefined`), and so is one with an escaped `+` (the `-subj` problem above). This happens in pkiaas before signing, so it's outside this library, but it shapes what the library is given.
3. **Validity dates depend on the host's time zone.** `CASignCSR` formats `-startdate`/`-enddate` in local time and appends `Z`. On a host that isn't on UTC, `notBefore` and `notAfter` shift by the UTC offset: in Asia/Tokyo, certificates aren't valid until 9 hours after issue. pkiaas containers and both IoT HSM installs (the Docker image's `TZ=UTC`, and `setup_ubuntu.sh`'s `timedatectl set-timezone UTC`) run on UTC, so only agents whose time zone was changed are affected. The harness pins `TZ=UTC`.
