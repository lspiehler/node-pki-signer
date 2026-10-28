# Upstream issues

Bugs in the libraries the native signer builds on, what the signer does about each one, and when that can go. Check this list whenever one of these libraries is upgraded.

## asn1js: OIDs that encode wrongly without an error

asn1js turns an OID string into DER in `LocalObjectIdentifierValueBlock.fromString` and `LocalSidValueBlock.toBER`. When it can't encode a number, it records `"Error during encoding SID value"` in the block's `error` and returns an empty value: the whole OID comes out as `06 00`. Nothing throws, so `@peculiar/asn1-schema` and the signer can't see it, and the broken OID ends up in a signed certificate.

Measured against OpenSSL 3.5 (`openssl asn1parse -genstr OID:<oid>`) for the third number of `1.2.<n>` at every bit length from 40 to 130 (2^k − 1, 2^k and a random value each), and for edge cases of the first two numbers:

| | asn1js 3.0.10 (pvutils 1.2.0) | asn1js 4.0.0 |
|---|---|---|
| A number from 2^49 to below 2^56 | empty OID: pvutils `utilToBase` writes at most 7 base-128 digits (49 bits), and the BigInt path keeps values of up to 8 bytes as JavaScript numbers that go back through it | correct |
| A number below 2^49, or of 2^56 and more | correct | correct |
| The second number under 2, from 2^53 − 80 (e.g. `2.9007199254740912`) | empty OID: the first two numbers are combined with `parseInt(x) + 80`, which has no BigInt path | the same (asn1js `master` on 2026-10-27 too) |
| `0.40` to `0.∞`, `1.40` to `1.∞` | encoded silently, e.g. `1.40` as `2.0`; OpenSSL refuses them (X.660) | the same |
| Decoding a number above 2^53 | wrong value | a placeholder such as `1.2.{1000000000000001}`, [asn1js issue 174](https://github.com/PeculiarVentures/asn1.js/issues/174) |

Reported upstream: [asn1js issue 225](https://github.com/PeculiarVentures/asn1.js/issues/225) (the second-number and X.660 rows, 2026-10-28).

The signer uses asn1js 4.0.0 with `@peculiar/asn1-*` 3.0.0 since 0.3.7 (0.3.6 and earlier: asn1js 3.0.10).

**What the signer does** (`src/extensions.ts`, `isOID`), for every OID it takes from input (extended key usages, policy identifiers, `customOIDs`, SAN RIDs and otherName types):
- OIDs that break X.660 are refused, as OpenSSL refuses them.
- An OID under 2 with a second number of 16 digits or more (10^15 is below 2^53 − 80) throws `UnsupportedError`, so `createSigner` falls back to OpenSSL, which encodes it correctly. Until 0.3.6, with asn1js 3.0.10, this applied to any number of 15 digits or more.

Shadow mode reads extension OIDs back with asn1js (`src/tbs-fields.ts`). A misread OID only changes the name it compares the extension under, never the bytes it compares.

**When this can change:** when asn1js encodes a second number under 2 from 2^53 − 80 correctly, remove the check from `isOID` and move the corpus cases `template with EKU OID with a 16-digit second number under 2` and `template policy OID with a 2^53 - 80 second number under 2` from `fallsBack` to the cases that must match. The cases with large numbers after the second one (15 digits, 2^53, 2^56, a 2.25 UUID) already must match byte for byte.

To check a new asn1js version directly, compare its encoding with OpenSSL's:

```js
import * as asn1js from 'asn1js';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';

for (const oid of ['1.2.562949953421312', '2.9007199254740912', '2.25.329800735698586629295641978511506172918']) {
  const ours = Buffer.from(new asn1js.ObjectIdentifier({ value: oid }).toBER()).toString('hex');
  execFileSync('openssl', ['asn1parse', '-genstr', `OID:${oid}`, '-out', 'oid.der', '-noout']);
  console.log(ours === readFileSync('oid.der').toString('hex') ? 'same  ' : 'DIFFER', oid);
}
```
