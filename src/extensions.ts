// Certificate extensions from options.extensions, as node-openssl-cert2 writes them into the
// [req_ext] section for `openssl ca`: in the key order of options.extensions, with the subject
// alternative name last. Each key is checked the way that config generator checks it.
import { AsnConvert, OctetString } from '@peculiar/asn1-schema';
import {
  AccessDescription,
  AuthorityInfoAccessSyntax,
  BasicConstraints,
  CertificatePolicies,
  CRLDistributionPoints,
  DistributionPoint,
  DistributionPointName,
  ExtendedKeyUsage,
  Extension,
  GeneralName,
  KeyUsage,
  KeyUsageFlags,
  OtherName,
  PolicyInformation,
  PolicyQualifierInfo,
  SubjectAlternativeName,
  id_ad_caIssuers,
  id_ad_ocsp,
  id_ce_basicConstraints,
  id_ce_certificatePolicies,
  id_ce_cRLDistributionPoints,
  id_ce_extKeyUsage,
  id_ce_keyUsage,
  id_ce_subjectAltName,
  id_pe_authorityInfoAccess,
  id_qt_csp,
} from '@peculiar/asn1-x509';
import * as asn1js from 'asn1js';
import { isIP } from 'node:net';
import { SignerError, UnsupportedError } from './errors.ts';

const step = 'build extensions';

// X.660: under 0 and 1 the second number is below 40
const oidPattern = /^([01]\.([0-9]|[1-3][0-9])|2\.(0|[1-9][0-9]*))(\.(0|[1-9][0-9]*))*$/;

// asn1js 4.0.0 adds 80 to the second number under 2 as a JavaScript number, so from 2^53 - 80 it encodes an empty
// OID; OIDs with a second number of 16 digits or more under 2 (10^15 is below 2^53 - 80) go to OpenSSL.
// docs/upstream-issues.md says when this can go
function isOID(value: string, what: string): boolean {
  if (!oidPattern.test(value)) return false;
  if (/^2\.[0-9]{16}/.test(value))
    throw new UnsupportedError(step, `${what} with a second number of 16 digits or more`);
  return true;
}

const printable = /^[A-Za-z0-9 '()+,\-./:=?]*$/;

// OpenSSL copies a config value's bytes into an IA5String as they are, so non-ASCII text comes out as
// its UTF-8 bytes; asn1js writes one byte per character, so pass the bytes as a binary string
const ia5 = (text: string): string => Buffer.from(text, 'utf8').toString('latin1');

const keyUsages: Record<string, KeyUsageFlags> = {
  digitalSignature: KeyUsageFlags.digitalSignature,
  nonRepudiation: KeyUsageFlags.nonRepudiation,
  keyEncipherment: KeyUsageFlags.keyEncipherment,
  dataEncipherment: KeyUsageFlags.dataEncipherment,
  keyAgreement: KeyUsageFlags.keyAgreement,
  keyCertSign: KeyUsageFlags.keyCertSign,
  cRLSign: KeyUsageFlags.cRLSign,
  encipherOnly: KeyUsageFlags.encipherOnly,
  decipherOnly: KeyUsageFlags.decipherOnly,
};

const extendedKeyUsages: Record<string, string> = {
  serverAuth: '1.3.6.1.5.5.7.3.1',
  clientAuth: '1.3.6.1.5.5.7.3.2',
  codeSigning: '1.3.6.1.5.5.7.3.3',
  emailProtection: '1.3.6.1.5.5.7.3.4',
  timeStamping: '1.3.6.1.5.5.7.3.8',
  OCSPSigning: '1.3.6.1.5.5.7.3.9',
  msCodeInd: '1.3.6.1.4.1.311.2.1.21',
  msCodeCom: '1.3.6.1.4.1.311.2.1.22',
  msCTLSign: '1.3.6.1.4.1.311.10.3.1',
  msEFS: '1.3.6.1.4.1.311.10.3.4',
  ipsecIKE: '1.3.6.1.5.5.7.3.17',
  ipsecEndSystem: '1.3.6.1.5.5.7.3.5',
  ipsecTunnel: '1.3.6.1.5.5.7.3.6',
  ipsecUser: '1.3.6.1.5.5.7.3.7',
};

// TLS feature extension (RFC 7633) and its one feature node-openssl-cert2 allows
const id_pe_tlsfeature = '1.3.6.1.5.5.7.1.24';
const tlsFeatures: Record<string, number> = { status_request: 5 };

// otherName types by OpenSSL short name
const otherNameTypes: Record<string, string> = { msUPN: '1.3.6.1.4.1.311.20.2.3' };

const der = (value: object) => AsnConvert.serialize(value);

function extension(extnID: string, critical: unknown, value: ArrayBuffer): Extension {
  return new Extension({ extnID, critical: Boolean(critical), extnValue: new OctetString(value) });
}

interface Usages {
  critical?: unknown;
  usages: unknown[];
}

function usages(name: string, value: unknown): Usages | undefined {
  if (!value || Object.keys(value).length === 0) return undefined;
  const { critical, usages } = value as Partial<Usages>;
  if (!Array.isArray(usages)) throw new SignerError(step, `${name} has no usages`);
  return usages.length > 0 ? { critical, usages } : undefined;
}

function keyUsage(value: unknown): Extension | undefined {
  const ku = usages('keyUsage', value);
  if (!ku) return undefined;
  let flags = 0;
  for (const usage of ku.usages) {
    const flag = typeof usage === 'string' && Object.hasOwn(keyUsages, usage) ? keyUsages[usage] : undefined;
    if (flag === undefined) throw new SignerError(step, `invalid keyUsage ${String(usage)}`);
    flags |= flag;
  }
  return extension(id_ce_keyUsage, ku.critical, der(new KeyUsage(flags)));
}

function extendedKeyUsage(value: unknown): Extension | undefined {
  const eku = usages('extendedKeyUsage', value);
  if (!eku) return undefined;
  const oids = eku.usages.map((usage) => {
    if (typeof usage === 'string' && Object.hasOwn(extendedKeyUsages, usage)) return extendedKeyUsages[usage] ?? '';
    if (typeof usage === 'string' && isOID(usage, 'extendedKeyUsage')) return usage;
    throw new SignerError(step, `invalid extendedKeyUsage ${String(usage)}`);
  });
  return extension(id_ce_extKeyUsage, eku.critical, der(new ExtendedKeyUsage(oids)));
}

function basicConstraints(value: unknown): Extension | undefined {
  if (!value || Object.keys(value).length === 0) return undefined;
  let critical = false;
  let cA = false;
  let pathLenConstraint: number | undefined;
  for (const [key, setting] of Object.entries(value)) {
    const expected = key === 'pathlen' ? 'number' : 'boolean';
    if (key !== 'critical' && key !== 'CA' && key !== 'pathlen') {
      throw new SignerError(step, `invalid basicConstraints ${key}`);
    }
    if (typeof setting !== expected) throw new SignerError(step, `basicConstraints ${key} must be a ${expected}`);
    if (key === 'critical') critical = setting as boolean;
    if (key === 'CA') cA = setting as boolean;
    if (key === 'pathlen' && (setting as number) >= 0) {
      // OpenSSL refuses some (1e21 is written as 1e+21) and asn1js others (1.5); leave them to OpenSSL
      if (!Number.isSafeInteger(setting))
        throw new UnsupportedError(step, `basicConstraints pathlen ${String(setting)}`);
      pathLenConstraint = setting as number;
    }
  }
  if (Object.keys(value).length === 1 && critical) {
    throw new SignerError(step, "basicConstraints can't contain only critical");
  }
  return extension(id_ce_basicConstraints, critical, der(new BasicConstraints({ cA, pathLenConstraint })));
}

// node-openssl-cert2 writes each value as a config line, and OpenSSL trims config values
function uri(value: unknown, name: string): GeneralName {
  if (typeof value !== 'string') throw new SignerError(step, `${name} must be strings`);
  return new GeneralName({ uniformResourceIdentifier: ia5(value.trim()) });
}

const list = (value: unknown, name: string): unknown[] => {
  if (!Array.isArray(value)) throw new SignerError(step, `${name} must be a list`);
  return value;
};

function authorityInfoAccess(value: unknown): Extension | undefined {
  if (!value || typeof value !== 'object') throw new SignerError(step, 'authorityInfoAccess must be an object');
  const { OCSP, caIssuers } = value as { OCSP?: unknown; caIssuers?: unknown };
  const descriptions = [
    ...(OCSP ? list(OCSP, 'OCSP') : []).map(
      (url) => new AccessDescription({ accessMethod: id_ad_ocsp, accessLocation: uri(url, 'OCSP') }),
    ),
    ...(caIssuers ? list(caIssuers, 'caIssuers') : []).map(
      (url) => new AccessDescription({ accessMethod: id_ad_caIssuers, accessLocation: uri(url, 'caIssuers') }),
    ),
  ];
  if (descriptions.length === 0) return undefined;
  return extension(id_pe_authorityInfoAccess, false, der(new AuthorityInfoAccessSyntax(descriptions)));
}

function crlDistributionPoints(value: unknown): Extension | undefined {
  const urls = list(value, 'crlDistributionPoints');
  if (urls.length === 0) return undefined;
  // one distribution point whose full name lists every URL
  const point = new DistributionPoint({
    distributionPoint: new DistributionPointName({ fullName: urls.map((url) => uri(url, 'crlDistributionPoints')) }),
  });
  return extension(id_ce_cRLDistributionPoints, false, der(new CRLDistributionPoints([point])));
}

function policies(value: unknown): Extension | undefined {
  const information: PolicyInformation[] = [];
  for (const policy of list(value, 'policies')) {
    const { policyIdentifier, CPS, userNotice } = (policy ?? {}) as Record<string, unknown>;
    if (!policyIdentifier) continue;
    if (typeof policyIdentifier !== 'string' || !isOID(policyIdentifier, 'policy identifier')) {
      throw new UnsupportedError(step, `policy identifier ${JSON.stringify(policyIdentifier)}`);
    }
    if (userNotice) throw new UnsupportedError(step, 'policy user notices');
    const cps = CPS ? (typeof CPS === 'string' ? [CPS] : list(CPS, 'CPS')) : [];
    const qualifiers = cps.map((url) => {
      const text = uri(url, 'CPS').uniformResourceIdentifier ?? '';
      return new PolicyQualifierInfo({
        policyQualifierId: id_qt_csp,
        qualifier: new asn1js.IA5String({ value: text }).toBER(),
      });
    });
    information.push(
      new PolicyInformation({ policyIdentifier, ...(qualifiers.length > 0 ? { policyQualifiers: qualifiers } : {}) }),
    );
  }
  if (information.length === 0) return undefined;
  return extension(id_ce_certificatePolicies, false, der(new CertificatePolicies(information)));
}

function tlsfeature(value: unknown): Extension | undefined {
  const features = list(value, 'tlsfeature').map((feature) => {
    const id = typeof feature === 'string' && Object.hasOwn(tlsFeatures, feature) ? tlsFeatures[feature] : undefined;
    if (id === undefined) throw new SignerError(step, `invalid tlsfeature ${String(feature)}`);
    return new asn1js.Integer({ value: id });
  });
  if (features.length === 0) return undefined;
  return extension(id_pe_tlsfeature, false, new asn1js.Sequence({ value: features }).toBER());
}

function hexBytes(hex: string): ArrayBuffer {
  const digits = hex.replace(/:/g, '');
  if (!/^([0-9a-fA-F]{2})+$/.test(digits)) throw new SignerError(step, 'customOIDs DER value is not hex');
  return new Uint8Array(Buffer.from(digits, 'hex')).buffer;
}

// the `OID=value` lines of customOIDs: [critical,]DER:<hex> or [critical,]ASN1:<type>[:<text>]
function customOID(value: unknown): Extension {
  const { OID, value: setting } = (value ?? {}) as { OID?: unknown; value?: unknown };
  if (typeof OID !== 'string' || typeof setting !== 'string') {
    throw new SignerError(step, 'customOIDs need an OID and a value');
  }
  const oid = OID.trim();
  if (!isOID(oid, 'customOIDs OID')) throw new UnsupportedError(step, `customOIDs OID ${oid}`);
  const match = /^(critical\s*,\s*)?(DER|ASN1):(.*)$/s.exec(setting.trim());
  if (!match) throw new UnsupportedError(step, `customOIDs value for ${oid}`);
  const [, critical, form, rest = ''] = match;
  if (form === 'DER') return extension(oid, critical, hexBytes(rest));
  const [type, ...text] = rest.split(':');
  const content = text.join(':');
  if (type === 'NULL' && text.length === 0) return extension(oid, critical, new asn1js.Null().toBER());
  if ((type === 'PRINTABLESTRING' || type === 'PRINTABLE') && printable.test(content)) {
    return extension(oid, critical, new asn1js.PrintableString({ value: content }).toBER());
  }
  throw new UnsupportedError(step, `customOIDs ASN1 value for ${oid}`);
}

function generalName(type: string, value: unknown): GeneralName {
  if (typeof value !== 'string') throw new SignerError(step, `SANs ${type} must be strings`);
  const trimmed = value.trim();
  switch (type) {
    case 'DNS':
    case 'email':
      return new GeneralName(type === 'DNS' ? { dNSName: ia5(trimmed) } : { rfc822Name: ia5(trimmed) });
    case 'URI':
      return uri(trimmed, 'SANs URI');
    case 'IP':
      // isIP takes an IPv6 zone (fe80::1%eth0), which OpenSSL refuses and the encoding would drop
      if (!isIP(trimmed) || trimmed.includes('%')) throw new SignerError(step, `invalid SANs IP ${trimmed}`);
      if (trimmed.includes('.') && trimmed.includes(':')) throw new UnsupportedError(step, 'IPv4-mapped IPv6 SANs');
      return new GeneralName({ iPAddress: trimmed });
    case 'RID':
      if (!isOID(trimmed, 'SANs RID')) throw new UnsupportedError(step, `SANs RID ${trimmed}`);
      return new GeneralName({ registeredID: trimmed });
    case 'otherName': {
      // <OID or short name>;UTF8:<text>
      const match = /^([^;]+);(UTF8|UTF8String):(.*)$/s.exec(trimmed);
      const name = match?.[1]?.trim() ?? '';
      const typeId = Object.hasOwn(otherNameTypes, name)
        ? otherNameTypes[name]
        : isOID(name, 'SANs otherName')
          ? name
          : undefined;
      const text = match?.[3] ?? '';
      if (!typeId) throw new UnsupportedError(step, 'this SANs otherName form');
      // OpenSSL reads the text's UTF-8 bytes as Latin-1 and encodes those characters as UTF-8 again
      return new GeneralName({
        otherName: new OtherName({ typeId, value: new asn1js.Utf8String({ value: ia5(text) }).toBER() }),
      });
    }
    case 'dirName':
      throw new UnsupportedError(step, 'SANs dirName');
    default:
      throw new SignerError(step, `invalid SANs type ${type}`);
  }
}

function subjectAltName(value: unknown): Extension | undefined {
  if (!value || Object.keys(value).length === 0) return undefined;
  const names = Object.entries(value as Record<string, unknown>).flatMap(([type, values]) =>
    list(values, `SANs ${type}`).map((v) => generalName(type, v)),
  );
  if (names.length === 0) throw new SignerError(step, 'SANs has no names');
  return extension(id_ce_subjectAltName, false, der(new SubjectAlternativeName(names)));
}

const builders: Record<string, (value: unknown) => Extension | undefined> = {
  keyUsage: (v) => (v ? keyUsage(v) : undefined),
  extendedKeyUsage: (v) => (v ? extendedKeyUsage(v) : undefined),
  basicConstraints,
  authorityInfoAccess,
  crlDistributionPoints,
  policies,
  tlsfeature,
};

/** The extensions after SKI and AKI, in the order `openssl ca` adds them. */
export function buildExtensions(extensions: Record<string, unknown> | null | undefined): Extension[] {
  const built: Extension[] = [];
  let san: Extension | undefined;
  for (const [key, value] of Object.entries(extensions ?? {})) {
    if (key === 'SANs') {
      san = subjectAltName(value);
    } else if (key === 'customOIDs') {
      if (value) built.push(...list(value, 'customOIDs').map(customOID));
    } else {
      const build = Object.hasOwn(builders, key) ? builders[key] : undefined;
      // node-openssl-cert2 refuses it today; a newer one may know it, so leave it to OpenSSL
      if (!build) throw new UnsupportedError(step, `extension ${key}`);
      const ext = build(value);
      if (ext) built.push(ext);
    }
  }
  if (san) built.push(san);
  return built;
}
