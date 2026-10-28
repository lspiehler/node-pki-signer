# 0002. Full subjects and UTC validity dates

Date: 2026-10-17. Status: accepted.

## Context
ADR 0001 says the native signer must issue the same certificates as node-openssl-cert2's `x509.CASignCSR` 0.7.34, and that any intended difference needs an ADR. The differential harness (phase 0, `docs/differential-harness.md`) found that the reference damages some subjects and validity dates:
- **Subjects cut at `/`, `+` and `\`.** `getDistinguishedName` builds `openssl ca -subj` escaping only spaces. A `/` in a value starts a new attribute, a `+` starts a multi-valued RDN, and a backslash disappears. `O=Ops/Infra, CN=host` is issued as `O=Ops`: the common name is lost. If the CSR's subject has an escaped `+`, `-subj` reads it as a second attribute of the same RDN and the request is refused. Values reach `-subj` from templates, admin overrides and CSRs.
- **Subjects lost to nested arrays.** The pkiaas template editor can save a subject value as a nested array, `countryName: [["US"]]`. 10 of the 87 template shapes on dev do. `getDistinguishedName` throws on it and falls back to `-subj /`, or to the attributes before the nested one. Certificates from these templates are issued with an empty or partial subject, without the CSR's common name.
- **Validity dates in local time.** `CASignCSR` formats `-startdate`/`-enddate` in the host's local time and appends `Z`. On a host that isn't on UTC, both dates shift by the UTC offset. pkiaas containers and the official IoT HSM installs run on UTC, so only agents whose time zone was changed are affected.

## Decision
The native signer fixes these instead of reproducing them (decided by the owner, 2026-10-16 and 2026-10-17):
- **Full subjects.** Every value in `options.subject` is issued exactly as given, one attribute per RDN. `/`, `+`, `\`, `=` and spaces are ordinary characters. A nested array is flattened: `[["US"]]` is issued as `US`.
- **UTC dates.** `startdate` and `enddate` are instants and are issued as such, whatever the host's time zone.

Everything else about the subject stays as `openssl ca` does it, so the subjects that come out whole today don't change:
- **Order:** attributes are issued in the order of node-openssl-cert2's `signing_policy` (C, ST, L, postalCode, street, O, OU, CN, emailAddress, jurisdiction C/ST/L, businessCategory, serialNumber, DC, SN, title, GN, UID, initials, generationQualifier, dnQualifier, pseudonym), not in the order given. Its config sets `preserve = yes`, but `openssl ca` still applies the policy order. Repeated attributes keep their given order.
- **String types and limits:** country, serialNumber and dnQualifier are PrintableString, emailAddress and domainComponent IA5String, everything else UTF8String. OpenSSL's size limits apply (country 2, common name 64, …). Values that break them are refused.
- **Empty values** are left out, as `-subj` skips them.
- **Unknown attribute names** are refused, as node-openssl-cert2 refuses them.

## Consequences
- **What changes for users:** certificates whose subject has `/`, `+` or `\`, or that come from a template with nested subject arrays, get their full subject. Requests that the reference refused because of an escaped `+` are signed. No other certificate changes.
- **The harness** lists these cases with the full subject each must have (`fullSubjects` in `test/differential/differential.test.ts`). For them only the subject may differ from the reference. The unit tests sign in Asia/Tokyo to check the dates.
- **Not fixed here:** pkiaas's `csr.parse` mangles CSR subjects before they reach any signer (`CN=a, b` becomes `a`, `O=Ops/Infra` becomes `Ops, Infra`, quotes are stripped). That's a separate pkiaas fix. The template editor that saves nested arrays should be fixed in pkiaas too.
- **The OpenSSL fallback** (node-openssl-cert2) still has these defects. When a request falls back, the old behaviour comes back for it.
- **Update, node-openssl-cert2 0.7.38 (2026-10-18):** node-openssl-cert2 now escapes `/`, `+` and `\` in `-subj`, and its `csr.parse` reads subjects correctly. The OpenSSL path issues those full subjects too, so the only subject difference left is nested subject arrays.
- **Update, 0.3.8 (2026-10-28, decided by the owner):** subject values that are numbers (`postalCode: 70112`) are issued as text. node-openssl-cert2 leaves such an attribute out without an error; the harness lists these cases in `fullSubjects`. Apart from that, the subject follows `openssl ca` in the remaining cases a review found: `preserveDN: true` keeps the given order, the ordered-list form `[{ type, value }]` from `csr.parse` is accepted, and without a `subject` option the CSR's subject is put in signing_policy order.
- **Update, node-openssl-cert2 0.7.39 (2026-10-19):** `signing_policy` now follows the CA/Browser Forum Baseline Requirements order (DC, C, ST, L, postalCode, street, O, SN, GN, OU, CN, emailAddress, jurisdiction C/ST/L, businessCategory, serialNumber, title, UID, initials, generationQualifier, dnQualifier, pseudonym, organizationIdentifier, unstructuredName, unstructuredAddress), and the last three are new. The native signer issues the same order, and the new attributes as UTF8String, like the reference.
