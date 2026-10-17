// The differential corpus: what PKIaaS.io signs, as inputs to x509.CASignCSR.
// - every template shape (test/corpus/templates.json: the presets and the distinct templates on dev,
//   values anonymized) on an RSA-2048 CA
// - every CA key type with every hash the platform offers
// - CSRs shaped like the enrollment clients' (ACME, Intune SCEP, MS CES), awkward subjects and SANs,
//   every subject key type
// - admin overrides, CT precertificates and final certificates, OCSP, timestamp and SCEP RA service certificates
import { readFileSync } from 'node:fs';
import { caKeySpecs, createCA, createCSR, type IssuingCA, type KeySpec } from './fixtures.ts';
import { platform, processOptions, type ProcessParams, type TemplateOptions } from './pkiaas-options.ts';
import { parseCSR, type SignOptions, type SignParams } from './reference.ts';

export interface CorpusCase {
  name: string;
  build(): Promise<SignParams>;
}

interface Template {
  name: string;
  options: TemplateOptions;
}

export const templates = JSON.parse(
  readFileSync(new URL('../corpus/templates.json', import.meta.url), 'utf8'),
) as Template[];

function template(name: string): Template {
  const found = templates.find((t) => t.name === name);
  if (!found) throw new Error(`no template ${name}`);
  return found;
}

const webServer = template('preset: Web Server');

// the clock of every request, so both paths get the same validity dates
const now = new Date(Math.floor(Date.now() / 1000) * 1000);

const keySpec = (name: string): KeySpec => {
  const found = caKeySpecs.find((s) => s.name === name);
  if (found) return found;
  if (name === 'ED25519') return { name, type: 'ed25519', pqc: false };
  throw new Error(`no key type ${name}`);
};

// one issuing CA per key type, created on first use
const cas = new Map<string, Promise<IssuingCA>>();
function issuingCA(name: string): Promise<IssuingCA> {
  let ca = cas.get(name);
  if (!ca) {
    ca = createCA(keySpec(name));
    cas.set(name, ca);
  }
  return ca;
}

interface CSRSpec {
  key?: string;
  subject?: string;
  config?: string[];
  attributes?: string[];
}

const standardCSR: CSRSpec = {
  subject: '/C=US/O=Example Org/CN=www.example.com',
  config: ['subjectAltName = DNS:www.example.com, DNS:example.com'],
};

interface CaseSpec {
  name: string;
  ca?: string;
  csr?: CSRSpec;
  template?: TemplateOptions | false;
  process?: Partial<Omit<ProcessParams, 'ca' | 'csroptions' | 'templateoptions' | 'now'>>;
  /** builds the options from the parsed CSR instead of processOptions, for paths that skip templates */
  options?: (csroptions: SignOptions, ca: IssuingCA['ca']) => SignOptions;
  /** changes the built options, for shapes processOptions never makes */
  adjust?: (options: SignOptions) => void;
}

function corpusCase(spec: CaseSpec): CorpusCase {
  return {
    name: spec.name,
    async build() {
      const csrSpec = spec.csr ?? standardCSR;
      const [ca, csr] = await Promise.all([
        issuingCA(spec.ca ?? 'RSA-2048'),
        createCSR(keySpec(csrSpec.key ?? 'RSA-2048'), csrSpec.subject ?? '/', csrSpec.config, csrSpec.attributes),
      ]);
      const csroptions = await parseCSR(csr);
      const templateoptions = spec.template ?? webServer.options;
      const options: SignOptions = spec.options
        ? spec.options(csroptions, ca.ca)
        : processOptions({
            ca: ca.ca,
            csroptions,
            templateoptions,
            template: templateoptions ? { policy_oid: '2.23.140.1.2.1', ct_logs: null } : false,
            now,
            ...spec.process,
          });
      spec.adjust?.(options);
      return { csr, options, ca: ca.cert, key: ca.key, password: ca.password };
    },
  };
}

const withHash = (options: TemplateOptions, hash: string): TemplateOptions => ({ ...options, hash });

// times are what processTemplate gives service certificates: now - 5 minutes to now + days
const serviceDates = (days: number) => ({
  startdate: new Date(now.getTime() - 5 * 60 * 1000),
  enddate: new Date(now.getTime() + days * 24 * 60 * 60 * 1000),
});

/** The service certificates' options from pkiaas lib/ca/createServiceCerts.js; `hash` is 'default' for PQC CAs. */
const service = {
  ocsp: (hash: string): SignOptions => ({
    subject: { commonName: 'PKIaaS.io OCSP Responder', countryName: 'US' },
    extensions: {
      basicConstraints: { critical: true, CA: false },
      keyUsage: { critical: true, usages: ['digitalSignature'] },
      extendedKeyUsage: { usages: ['OCSPSigning'] },
      customOIDs: [{ OID: '1.3.6.1.5.5.7.48.1.5', value: 'ASN1:NULL' }],
    },
    hash,
    ...serviceDates(365),
  }),
  timestamp: (hash: string): SignOptions => ({
    subject: { commonName: 'PKIaaS.io Timestamp Responder', countryName: 'US' },
    extensions: {
      keyUsage: { critical: true, usages: ['digitalSignature'] },
      extendedKeyUsage: { critical: true, usages: ['timeStamping'] },
      basicConstraints: { CA: false, critical: true },
    },
    hash,
    ...serviceDates(3650),
  }),
  scepRA: (): SignOptions => ({
    subject: { countryName: 'US' },
    extensions: {
      keyUsage: { critical: false, usages: [] },
      extendedKeyUsage: { critical: false, usages: [] },
    },
    hash: 'sha256',
    ...serviceDates(365),
  }),
};

// a v2 certificate template extension as MS CES sends it, and pkiaas's leading-space OID (api/ms/ces/request.js)
const cesTemplateDER =
  '30:2E:06:26:2B:06:01:04:01:82:37:15:08:87:D1:A5:5B:85:E1:9D:2D:84:F5:83:13:83:CD:F6:3F:82:D5:A0:12:81:3E:86:B6:A6:1E:02:01:64:02:01:00';
// an SCT list extension value as lib/ca/CTLog.js builds it: one SCT inside an OCTET STRING
const sctListDER =
  'DER:04:3B:00:39:00:37:00:' +
  Array.from({ length: 32 }, (_, i) => (i + 0x10).toString(16).toUpperCase().padStart(2, '0')).join(':') +
  ':00:00:01:92:00:00:00:00:00:00:04:03:00:08:30:06:02:01:01:02:01:01';

const hashes = ['sha1', 'sha256', 'sha384', 'sha512'];

export const corpus: CorpusCase[] = [
  ...templates.map((t) => corpusCase({ name: `template ${t.name}`, template: t.options })),

  ...caKeySpecs.flatMap((spec) =>
    // PQC: 'default' is what pkiaas uses for service certificates, sha256 what the preset templates carry
    (spec.pqc ? ['default', 'sha256'] : hashes).map((hash) =>
      corpusCase({ name: `CA ${spec.name} ${hash}`, ca: spec.name, template: withHash(webServer.options, hash) }),
    ),
  ),

  corpusCase({
    name: 'CSR ACME (empty subject, SANs only)',
    csr: { subject: '/', config: ['subjectAltName = DNS:example.net, DNS:*.example.net'] },
  }),
  corpusCase({
    name: 'CSR Intune SCEP (UPN, challenge)',
    csr: {
      subject: '/CN=user@example.com',
      config: [
        'subjectAltName = otherName:1.3.6.1.4.1.311.20.2.3;UTF8:user@example.com, email:user@example.com',
        'keyUsage = critical, digitalSignature, keyEncipherment',
        'extendedKeyUsage = clientAuth',
      ],
      attributes: ['challengePassword = not-a-real-challenge'],
    },
  }),
  corpusCase({
    name: 'CSR MS CES (template extension)',
    csr: { subject: '/CN=WS01.corp.example.com', config: [`1.3.6.1.4.1.311.21.7 = DER:${cesTemplateDER}`] },
    process: { templateOID: { OID: ' 1.3.6.1.4.1.311.21.7', value: `DER:${cesTemplateDER}` } },
  }),
  corpusCase({
    name: 'CSR UTF-8 subject',
    csr: {
      subject: '/C=FR/O=Société Générale/CN=Ünïcødé 日本語 сервер',
      config: ['subjectAltName = DNS:xn--bcher-kva.example'],
    },
  }),
  corpusCase({
    // csr.parse keeps the escaped +, and -subj then reads it as a multi-valued RDN and refuses it
    name: 'CSR punctuation in subject',
    csr: { subject: '/C=US/O=Smith, Jones & Co./OU=R&D (Ops)/CN=a\\+b "quoted" #1 <x>; y', config: [] },
  }),
  // csr.parse turns `a=b` into an attribute named "undefined", which the reference refuses
  corpusCase({ name: 'CSR equals sign in subject', csr: { subject: '/C=US/CN=a\\=b', config: [] } }),
  corpusCase({
    name: 'CSR slash and backslash in subject',
    csr: { subject: '/C=US/O=Ops\\/Infra/CN=back\\\\slash', config: [] },
  }),
  corpusCase({
    name: 'CSR multi-valued and less common attributes',
    csr: {
      subject:
        '/DC=com/DC=example/C=US/ST=Louisiana/L=New Orleans/postalCode=70112/street=1 Main St/O=Example Org' +
        '/OU=One/OU=Two/title=Engineer/GN=Ada/SN=Lovelace/serialNumber=A1234/emailAddress=ada@example.com/CN=Ada Lovelace',
      config: [],
    },
  }),
  corpusCase({
    name: 'CSR 64-character common name',
    csr: { subject: `/CN=${'a'.repeat(52)}.example.com`, config: [] },
  }),
  corpusCase({
    name: 'CSR every SAN type',
    csr: {
      subject: '/CN=all-sans.example.com',
      config: [
        'subjectAltName = DNS:all-sans.example.com, IP:192.0.2.10, IP:2001:db8::10, email:ops@example.com, ' +
          'URI:https://example.com/device/1, otherName:1.3.6.1.4.1.311.20.2.3;UTF8:device@example.com',
      ],
    },
  }),
  // must-staple: csr.parse passes the CSR's TLS feature extension through as `tlsfeature`
  corpusCase({
    name: 'CSR must-staple (TLS feature)',
    csr: { ...standardCSR, config: [...(standardCSR.config ?? []), 'tlsfeature = status_request'] },
  }),
  ...['RSA-4096', 'EC-P256', 'EC-P384', 'EC-P521', 'ED25519', 'ML-DSA-65', 'SLH-DSA-SHA2-128F'].map((key) =>
    corpusCase({ name: `CSR key ${key}`, csr: { ...standardCSR, key } }),
  ),

  corpusCase({
    name: 'admin override (subject, extensions, days)',
    process: {
      requestoptions: {
        subject: { commonName: 'override.example.com', organizationName: 'Override Org' },
        extensions: { SANs: { DNS: ['override.example.com'], IP: ['198.51.100.7'] } },
        days: 90,
      },
    },
  }),
  // subject values that reach -subj unescaped: admins and templates can set any value
  ...Object.entries({
    slash: 'Ops/Infra',
    plus: 'a+b',
    equals: 'a=b',
    backslash: 'back\\slash',
    comma: 'Smith, Jones',
    quotes: '"quoted"',
    'leading and trailing spaces': '  padded  ',
    'two spaces': 'two  spaces',
    'UTF-8': 'Ünïcødé 日本語',
  }).map(([what, value]) =>
    corpusCase({
      name: `admin override subject with ${what}`,
      process: {
        requestoptions: { subject: { countryName: 'US', organizationName: value, commonName: 'override.example.com' } },
      },
    }),
  ),
  // every attribute node-openssl-cert2 accepts, out of order: string types, limits and policy order
  corpusCase({
    name: 'admin override subject with every attribute',
    process: {
      requestoptions: {
        subject: {
          pseudonym: 'Pseudo',
          dnQualifier: 'qualifier-1',
          generationQualifier: 'Jr.',
          initials: 'AL',
          UID: 'ada',
          givenName: 'Ada',
          title: 'Engineer',
          surname: 'Lovelace',
          domainComponent: ['example', 'com'],
          serialNumber: 'A1234',
          businessCategory: 'Private Organization',
          jurisdictionLocalityName: 'New Orleans',
          jurisdictionStateOrProvinceName: 'Louisiana',
          jurisdictionCountryName: 'US',
          emailAddress: 'ada@example.com',
          commonName: 'every.example.com',
          organizationalUnitName: ['One', 'Two'],
          organizationName: 'Example Org',
          streetAddress: '1 Main St',
          postalCode: '70112',
          localityName: 'New Orleans',
          stateOrProvinceName: 'Louisiana',
          countryName: 'US',
        },
      },
    },
  }),
  // without a subject the CSR's own subject is kept (pkiaas always sends one)
  corpusCase({
    name: 'no subject in options',
    csr: { subject: '/C=US/O=Example Org/OU=Ops/CN=keep.example.com', config: [] },
    adjust: (options) => {
      delete options.subject;
    },
  }),
  corpusCase({
    name: 'admin override (template subject merged)',
    template: template('dev template 1').options,
    process: { requestoptions: { hash: 'sha512' } },
  }),
  // pkiaas lib/admin/ca/signcert.js: no template, AIA and CDP only, one day backdated
  corpusCase({
    name: 'admin sign certificate (legacy /admin)',
    options: (csroptions, ca) => {
      const name = ca.name.replace(/[^a-zA-Z0-9-_]/g, '');
      return {
        ...csroptions,
        extensions: {
          ...csroptions.extensions,
          authorityInfoAccess: {
            caIssuers: [`http://${platform.ISSUERFQDN}/${ca.publicid}/${name}ca.crt`],
            OCSP: [`http://${platform.OCSPFQDN}`],
          },
          crlDistributionPoints: [`http://${platform.CRLFQDN}/${ca.publicid}/${name}.crl`],
        },
        startdate: new Date(now.getTime() - 24 * 60 * 60 * 1000),
        enddate: new Date(now.getTime() + 365 * 24 * 60 * 60 * 1000),
      };
    },
  }),
  corpusCase({
    name: 'CT precertificate (poison)',
    process: { template: { policy_oid: '2.23.140.1.2.1', ct_logs: '[1]' }, finalcert: false },
  }),
  corpusCase({
    name: 'CT final certificate (SCT list)',
    process: { template: { policy_oid: '2.23.140.1.2.1', ct_logs: '[1]' }, asn1sct: sctListDER },
  }),

  ...['RSA-2048', 'EC-P384', 'ML-DSA-65', 'SLH-DSA-SHAKE-128F'].flatMap((ca) => {
    const hash = keySpec(ca).pqc ? 'default' : 'sha256';
    return [
      corpusCase({
        name: `service OCSP signing on ${ca}`,
        ca,
        csr: { subject: '/CN=PKIaaS.io OCSP Responder/C=US' },
        template: false,
        process: { requestoptions: service.ocsp(hash), template: false },
      }),
      corpusCase({
        name: `service timestamping on ${ca}`,
        ca,
        csr: { subject: '/CN=PKIaaS.io Timestamp Responder/C=US' },
        template: false,
        process: { requestoptions: service.timestamp(hash), template: false },
      }),
    ];
  }),
  corpusCase({
    name: 'service SCEP RA',
    csr: { subject: '/C=US' },
    template: false,
    process: { requestoptions: service.scepRA(), template: false },
  }),
];
