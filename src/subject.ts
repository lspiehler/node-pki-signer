// The certificate subject from options.subject. Every value is kept exactly as given, one per RDN
// (ADR 0002), in the order of node-openssl-cert2's signing_policy, which `openssl ca` applies. String types and size limits are OpenSSL's for `openssl ca -utf8` with the
// default string_mask (utf8only): PrintableString or IA5String where X.520 or PKCS #9 require it,
// UTF8String everywhere else.
import { AttributeTypeAndValue, AttributeValue, Name, RelativeDistinguishedName } from '@peculiar/asn1-x509';
import { SignerError } from './errors.ts';

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

/** The subject Name; an empty one for a false, null or missing subject. */
export function buildSubject(subject: Record<string, unknown> | false | null | undefined): Name {
  const given = subject === false ? {} : (subject ?? {});
  for (const name of Object.keys(given)) {
    if (!Object.hasOwn(attributes, name)) throw new SignerError('build subject', `invalid attribute ${name}`);
  }
  const rdns: RelativeDistinguishedName[] = [];
  for (const [name, spec] of Object.entries(attributes)) {
    if (!Object.hasOwn(given, name)) continue;
    const values = given[name];
    // pkiaas's template editor can save [["US"]]; ADR 0002 issues it as US
    const list: unknown[] = Array.isArray(values) ? values.flat(Infinity) : [values];
    for (const value of list) {
      if (typeof value !== 'string') throw new SignerError('build subject', `${name} is not a string`);
      // like `openssl -subj`, which skips attributes without a value
      if (value === '') continue;
      rdns.push(
        new RelativeDistinguishedName([
          new AttributeTypeAndValue({ type: spec.oid, value: attributeValue(name, spec, value) }),
        ]),
      );
    }
  }
  return new Name(rdns);
}
