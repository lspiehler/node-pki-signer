// The certificate subject from options.subject. Every value is kept exactly as given, one per RDN
// (ADR 0002), in the order of node-openssl-cert2's signing_policy, which `openssl ca` applies, or as given
// with preserveDN (`openssl ca -preserveDN`). String types and size limits are OpenSSL's for `openssl ca -utf8` with the
// default string_mask (utf8only): PrintableString or IA5String where X.520 or PKCS #9 require it,
// UTF8String everywhere else.
import { AttributeTypeAndValue, AttributeValue, Name, RelativeDistinguishedName } from '@peculiar/asn1-x509';
import { SignerError, UnsupportedError } from './errors.ts';

type StringType = 'printableString' | 'ia5String' | 'utf8String';

interface AttributeSpec {
  oid: string;
  type: StringType;
  min?: number;
  max?: number;
}

const ub = {
  name: 32768,
  commonName: 64,
  locality: 128,
  state: 128,
  organization: 64,
  unit: 64,
  email: 128,
  serial: 64,
};

/** The subject attributes node-openssl-cert2 accepts, by its names, in its signing_policy order. */
const attributes: Record<string, AttributeSpec> = {
  domainComponent: { oid: '0.9.2342.19200300.100.1.25', type: 'ia5String' },
  countryName: { oid: '2.5.4.6', type: 'printableString', min: 2, max: 2 },
  stateOrProvinceName: { oid: '2.5.4.8', type: 'utf8String', max: ub.state },
  localityName: { oid: '2.5.4.7', type: 'utf8String', max: ub.locality },
  postalCode: { oid: '2.5.4.17', type: 'utf8String' },
  streetAddress: { oid: '2.5.4.9', type: 'utf8String' },
  organizationName: { oid: '2.5.4.10', type: 'utf8String', max: ub.organization },
  surname: { oid: '2.5.4.4', type: 'utf8String', max: ub.name },
  givenName: { oid: '2.5.4.42', type: 'utf8String', max: ub.name },
  organizationalUnitName: { oid: '2.5.4.11', type: 'utf8String', max: ub.unit },
  commonName: { oid: '2.5.4.3', type: 'utf8String', max: ub.commonName },
  emailAddress: { oid: '1.2.840.113549.1.9.1', type: 'ia5String', max: ub.email },
  jurisdictionCountryName: { oid: '1.3.6.1.4.1.311.60.2.1.3', type: 'printableString', min: 2, max: 2 },
  jurisdictionStateOrProvinceName: { oid: '1.3.6.1.4.1.311.60.2.1.2', type: 'utf8String' },
  jurisdictionLocalityName: { oid: '1.3.6.1.4.1.311.60.2.1.1', type: 'utf8String' },
  businessCategory: { oid: '2.5.4.15', type: 'utf8String' },
  serialNumber: { oid: '2.5.4.5', type: 'printableString', max: ub.serial },
  title: { oid: '2.5.4.12', type: 'utf8String' },
  UID: { oid: '0.9.2342.19200300.100.1.1', type: 'utf8String' },
  initials: { oid: '2.5.4.43', type: 'utf8String', max: ub.name },
  generationQualifier: { oid: '2.5.4.44', type: 'utf8String' },
  dnQualifier: { oid: '2.5.4.46', type: 'printableString' },
  pseudonym: { oid: '2.5.4.65', type: 'utf8String' },
  organizationIdentifier: { oid: '2.5.4.97', type: 'utf8String' },
  unstructuredName: { oid: '1.2.840.113549.1.9.2', type: 'utf8String' },
  unstructuredAddress: { oid: '1.2.840.113549.1.9.8', type: 'utf8String' },
};

const printable = /^[A-Za-z0-9 '()+,\-./:=?]*$/;
// eslint-disable-next-line no-control-regex
const ia5 = /^[\x00-\x7f]*$/;

function attributeValue(name: string, spec: AttributeSpec, value: string): AttributeValue {
  // asn1js can't encode a lone surrogate; OpenSSL writes U+FFFD
  if (!value.isWellFormed()) throw new UnsupportedError('build subject', `${name} has a lone surrogate`);
  // OpenSSL counts characters, not bytes
  const length = Array.from(value).length;
  if (spec.min !== undefined && length < spec.min) {
    throw new SignerError('build subject', `${name} must be at least ${spec.min} characters`);
  }
  if (spec.max !== undefined && length > spec.max) {
    throw new SignerError('build subject', `${name} must be at most ${spec.max} characters`);
  }
  if (spec.type === 'printableString' && !printable.test(value)) {
    throw new SignerError('build subject', `${name} has characters a PrintableString can't hold`);
  }
  if (spec.type === 'ia5String' && !ia5.test(value)) {
    throw new SignerError('build subject', `${name} has characters an IA5String can't hold`);
  }
  return new AttributeValue({ [spec.type]: value });
}

/** A subject value as a string; ADR 0002: numbers are issued as text (`postalCode: 70112`). */
function text(name: string, value: unknown): string {
  if (typeof value === 'string') return value;
  if ((typeof value === 'number' && Number.isFinite(value)) || typeof value === 'bigint') return String(value);
  throw new SignerError('build subject', `${name} is not a string`);
}

/** The (name, value) pairs of a subject object or of an ordered list [{ type, value }], in the given order. */
function pairs(subject: unknown): [string, string][] {
  if (Array.isArray(subject)) {
    // an empty list is an empty subject, as node-openssl-cert2 writes `-subj /`
    return subject.map((entry: unknown, i) => {
      const { type, value } = (entry ?? {}) as { type?: unknown; value?: unknown };
      if (typeof type !== 'string' || !Object.hasOwn(attributes, type)) {
        throw new SignerError('build subject', `invalid attribute ${i}`);
      }
      return [type, text(type, value)];
    });
  }
  const given = (subject ?? {}) as Record<string, unknown>;
  return Object.entries(given).flatMap(([name, values]) => {
    if (!Object.hasOwn(attributes, name)) throw new SignerError('build subject', `invalid attribute ${name}`);
    // pkiaas's template editor can save [["US"]]; ADR 0002 issues it as US
    const list: unknown[] = Array.isArray(values) ? values.flat(Infinity) : [values];
    return list.map((value): [string, string] => [name, text(name, value)]);
  });
}

const policyOrder = Object.keys(attributes);
const policyOIDs = policyOrder.map((name) => attributes[name]?.oid);

/**
 * A CSR's subject as `openssl ca` issues it without `-subj`: one attribute per RDN (a multi-valued RDN is
 * split), in signing_policy order, repeated attributes in their given order; or as it is with preserveDN.
 */
export function orderSubject(subject: Name, preserveDN = false): Name {
  if (preserveDN) return subject;
  const ranked = [...subject].flatMap((rdn) =>
    [...rdn].map((attribute) => {
      const rank = policyOIDs.indexOf(attribute.type);
      // OpenSSL leaves out attributes outside the policy
      if (rank < 0) throw new UnsupportedError('build subject', 'a CSR subject attribute outside the signing policy');
      return { rank, rdn: new RelativeDistinguishedName([attribute]) };
    }),
  );
  // Array.prototype.sort is stable
  return new Name(ranked.sort((a, b) => a.rank - b.rank).map(({ rdn }) => rdn));
}

/**
 * The subject Name; an empty one for a false, null or missing subject. Without `preserveDN` the attributes
 * follow the signing_policy order and repeated ones keep their given order, as `openssl ca` does.
 */
export function buildSubject(subject: unknown, preserveDN = false): Name {
  const given = pairs(subject === false ? {} : subject);
  // Array.prototype.sort is stable
  if (!preserveDN) given.sort(([a], [b]) => policyOrder.indexOf(a) - policyOrder.indexOf(b));
  const rdns: RelativeDistinguishedName[] = [];
  for (const [name, value] of given) {
    // like `openssl -subj`, which skips attributes without a value
    if (value === '') continue;
    const spec = attributes[name];
    if (!spec) throw new SignerError('build subject', `invalid attribute ${name}`);
    rdns.push(
      new RelativeDistinguishedName([
        new AttributeTypeAndValue({ type: spec.oid, value: attributeValue(name, spec, value) }),
      ]),
    );
  }
  return new Name(rdns);
}
