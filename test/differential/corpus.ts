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
  /** a CSR from test/corpus/, instead of a new one */
  file?: string;
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
        csrSpec.file
          ? readFileSync(new URL(`../corpus/${csrSpec.file}`, import.meta.url), 'utf8')
          : createCSR(keySpec(csrSpec.key ?? 'RSA-2048'), csrSpec.subject ?? '/', csrSpec.config, csrSpec.attributes),
      ]);
      // OpenSSL 3.5 doesn't verify CSRs with a version other than v1, so pkiaas refuses them (ADR 0005)
      const csroptions = await parseCSR(csr, !csrSpec.file?.startsWith('csr-version-'));
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

const hashes = ['sha1', 'sha224', 'sha256', 'sha384', 'sha512'];

/**
 * The hashes the corpus signs with for a CA key type. For PQC, 'default' is what pkiaas uses for
 * service certificates, sha256 what the preset templates carry.
 */
export const caHashes = (spec: KeySpec) => (spec.pqc ? ['default', 'sha256'] : hashes);

/** Every CA key type with every hash: the cases each key backend is checked with. */
export const caKeyCases: (CorpusCase & { spec: KeySpec; hash: string })[] = caKeySpecs.flatMap((spec) =>
  caHashes(spec).map((hash) => ({
    spec,
    hash,
    ...corpusCase({ name: `CA ${spec.name} ${hash}`, ca: spec.name, template: withHash(webServer.options, hash) }),
  })),
);

export const corpus: CorpusCase[] = [
  ...templates.map((t) => corpusCase({ name: `template ${t.name}`, template: t.options })),

  ...caKeyCases,

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
    // commas, quotes, an escaped + and RFC 2253 specials; node-openssl-cert2 before 0.7.38 mangled or refused them
    name: 'CSR punctuation in subject',
    csr: { subject: '/C=US/O=Smith, Jones & Co./OU=R&D (Ops)/CN=a\\+b "quoted" #1 <x>; y', config: [] },
  }),
  // before node-openssl-cert2 0.7.38, csr.parse turned `a=b` into an attribute named "undefined" and the reference refused it
  corpusCase({ name: 'CSR equals sign in subject', csr: { subject: '/C=US/CN=a\\=b', config: [] } }),
  // ADR 0005: CSRs with version 2 instead of v1 (0), from https://github.com/openssl/openssl/issues/28761;
  // `openssl ca` 3.5 refuses them
  corpusCase({ name: 'CSR version 2 (Meraki MDM)', csr: { file: 'csr-version-2-meraki.pem' } }),
  corpusCase({ name: 'CSR version 2 (SCEP CA request)', csr: { file: 'csr-version-2-scep-ca.pem' } }),
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
  corpusCase({
    name: 'CSR RID and otherName with a 15-digit number',
    csr: {
      subject: '/CN=rid.example.com',
      config: [
        'subjectAltName = DNS:rid.example.com, RID:1.3.6.1.4.1.562949953421312, ' +
          'otherName:1.3.6.1.4.1.562949953421312;UTF8:device@example.com',
      ],
    },
  }),
  corpusCase({
    name: 'custom OID with a 15-digit number',
    adjust: (options) => {
      options.extensions = {
        ...options.extensions,
        customOIDs: [{ OID: '1.3.6.1.4.1.562949953421312', value: 'ASN1:NULL' }],
      };
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
  // requesters choose their SANs: config variables must come out literally, not expanded
  corpusCase({
    name: 'admin override SANs with config variables',
    process: {
      requestoptions: {
        extensions: { SANs: { DNS: ['$ENV::HOME.example.com'], email: ['${req::prompt}@example.com'] } },
      },
    },
  }),
  // non-ASCII SANs: OpenSSL writes the UTF-8 bytes into the IA5String as they are (4-byte emoji,
  // 3-byte CJK, 2-byte Arabic), and requesters use them to test unusual characters
  corpusCase({
    name: 'admin override SANs with non-ASCII characters',
    process: {
      requestoptions: {
        extensions: {
          SANs: {
            DNS: ['😊.com', '中文.example', 'مثال.example'],
            email: ['josé@例え.example', '😊@example.com'],
            URI: ['https://例え.example/😊'],
          },
        },
      },
    },
  }),
  corpusCase({
    name: 'admin override SANs with a non-ASCII UPN',
    process: { requestoptions: { extensions: { SANs: { otherName: ['msUPN;UTF8:josé😊@例え.example'] } } } },
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
    // OpenSSL would expand these in openssl.cnf; node-openssl-cert2 0.7.37 escapes them
    'config variable': '$ENV::HOME ${req::prompt} $$ # x',
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
          unstructuredAddress: '1 Main St, New Orleans',
          unstructuredName: 'device-01.example.com',
          organizationIdentifier: 'VATUS-12345',
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
  // the attributes node-openssl-cert2 0.7.39 added, with UTF-8 values: their string types
  corpusCase({
    name: 'admin override subject with UTF-8 organizationIdentifier, unstructuredName and unstructuredAddress',
    process: {
      requestoptions: {
        subject: {
          organizationIdentifier: 'NTRDE-Société 日本',
          unstructuredName: 'Gerät 日本',
          unstructuredAddress: 'Straße 1, Köln',
          commonName: 'pkcs9.example.com',
        },
      },
    },
  }),
  // CSR subjects in other orders are issued in the BR order: DC first, SN and GN before OU and CN
  ...Object.entries({
    'DC last': '/CN=dc.example.com/OU=Ops/O=Example Org/DC=example/DC=com',
    'SN and GN after CN': '/C=US/O=Example Org/OU=People/CN=Ada Lovelace/SN=Lovelace/GN=Ada',
    'GN before SN, DC in the middle': '/GN=Ada/CN=Ada Lovelace/DC=example/SN=Lovelace/DC=com/C=US',
    'organizationIdentifier, unstructuredName and unstructuredAddress first':
      '/unstructuredAddress=1 Main St/unstructuredName=device-01/organizationIdentifier=VATUS-12345/CN=pkcs9.example.com/C=US',
  }).map(([what, subject]) => corpusCase({ name: `CSR subject order: ${what}`, csr: { subject, config: [] } })),
  // without a subject the CSR's own subject is kept (pkiaas always sends one)
  corpusCase({
    name: 'no subject in options',
    csr: { subject: '/C=US/O=Example Org/OU=Ops/CN=keep.example.com', config: [] },
    adjust: (options) => {
      delete options.subject;
    },
  }),
  // template shapes from a scan of the production templates (2026-10-18) that dev doesn't have
  ...Object.entries({
    // 36500 and 72000 reach past 2049 (GeneralizedTime); the largest overflow the year 9999
    'days 36500': (t) => (t.days = 36500),
    'days 72000': (t) => (t.days = 72000),
    'days 9999999': (t) => (t.days = 9999999),
    'days 999999999': (t) => (t.days = 999999999),
    'hash SHA256': (t) => (t.hash = 'SHA256'),
    'hash with a trailing space': (t) => (t.hash = 'sha256 '),
    'no hash': (t) => delete t.hash,
    'IPsec and Microsoft EKU names': (t) =>
      (t.extensions.extendedKeyUsage = {
        usages: ['ipsecIKE', 'ipsecEndSystem', 'ipsecTunnel', 'ipsecUser', 'msCTLSign', 'msEFS'],
      }),
    'unknown EKU name': (t) => (t.extensions.extendedKeyUsage = { usages: ['serverAuth', 'notAnEKUName'] }),
    // X.660: OpenSSL refuses a second number above 39 under 0 and 1; asn1js encoded 1.40 as 2.0
    'EKU OID 1.40': (t) => (t.extensions.extendedKeyUsage = { usages: ['serverAuth', '1.40'] }),
    // asn1js 3.0.10 encoded some numbers of 2^49 (15 digits) and more wrongly
    'EKU OID with a 14-digit number': (t) =>
      (t.extensions.extendedKeyUsage = { usages: ['serverAuth', '1.3.6.1.4.1.99999999999999'] }),
    'EKU OID with a 15-digit number': (t) =>
      (t.extensions.extendedKeyUsage = { usages: ['serverAuth', '1.3.6.1.4.1.562949953421312'] }),
    // asn1js 4.0.0 encodes a second number under 2 from 2^53 - 80 as an empty OID
    'EKU OID with a 15-digit second number under 2': (t) =>
      (t.extensions.extendedKeyUsage = { usages: ['serverAuth', '2.999999999999999.1'] }),
    'EKU OID with a 16-digit second number under 2': (t) =>
      (t.extensions.extendedKeyUsage = { usages: ['serverAuth', '2.1000000000000000.1'] }),
    'encipherOnly and decipherOnly': (t) =>
      (t.extensions.keyUsage = {
        critical: true,
        usages: ['digitalSignature', 'keyAgreement', 'encipherOnly', 'decipherOnly'],
      }),
    'non-critical basicConstraints': (t) => (t.extensions.basicConstraints = { critical: false, CA: false }),
    'CA pathlen 10': (t) => (t.extensions.basicConstraints = { critical: true, CA: true, pathlen: 10 }),
    'empty custom AIA URL': (t) => (t.extensions.authorityInfoAccess = { caIssuers: { customURL: '' }, OCSP: true }),
    'custom AIA URL that is not a URL': (t) =>
      (t.extensions.authorityInfoAccess = { caIssuers: { customURL: 'issuer.example.net' }, OCSP: true }),
    // UTF-8 bytes go into the IA5String as they are, as with SANs
    'custom AIA URL with non-ASCII characters': (t) =>
      (t.extensions.authorityInfoAccess = { caIssuers: { customURL: 'http://例え.example/😊/مثال.crt' }, OCSP: true }),
    'custom AIA URLs with a tab and spaces': (t) =>
      (t.extensions.authorityInfoAccess = {
        caIssuers: { customURL: '\thttp://aia1.example.net/issuer.crt, http://aia2.example.net/issuer.crt ' },
        OCSP: true,
      }),
  } satisfies Record<string, (t: TemplateOptions) => unknown>).map(([what, change]) => {
    const t = structuredClone(webServer.options);
    change(t);
    return corpusCase({ name: `template with ${what}`, template: t });
  }),
  // a template's policy_oid is NULL in a fifth of production's templates, and can be empty or anyPolicy
  ...Object.entries({
    NULL: null,
    empty: '',
    anyPolicy: '2.5.29.32.0',
    '1.40': '1.40',
    'with a 14-digit number': '1.2.99999999999999',
    'with a 15-digit number': '1.2.562949953421312',
    'with a 2^53 number': '1.2.9007199254740993',
    'with a 2^56 number': '1.2.72057594037927936',
    'with a UUID (2.25)': '2.25.329800735698586629295641978511506172918',
    'with a 15-digit second number under 2': '2.999999999999999',
    'with a 2^53 - 80 second number under 2': '2.9007199254740912',
  }).map(([what, policy_oid]) =>
    corpusCase({
      name: `template policy OID ${what}`,
      process: { template: { policy_oid, ct_logs: null } },
    }),
  ),
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
  // review of 0.3.7 (2026-10-28): subject order, repeated extensions and values OpenSSL refuses
  ...Object.entries({
    'subject with preserveDN': (o) => {
      o.preserveDN = true;
      o.subject = { commonName: 'p.example.com', organizationalUnitName: ['B', 'A'], countryName: 'US' };
    },
    'subject list': (o) =>
      (o.subject = [
        { type: 'commonName', value: 'l.example.com' },
        { type: 'organizationalUnitName', value: 'B' },
        { type: 'countryName', value: 'US' },
        { type: 'organizationalUnitName', value: '' },
      ]),
    'subject list with preserveDN': (o) => {
      o.preserveDN = true;
      o.subject = [
        { type: 'commonName', value: 'l.example.com' },
        { type: 'organizationalUnitName', value: 'B' },
        { type: 'countryName', value: 'US' },
        { type: 'organizationalUnitName', value: 'A' },
      ];
    },
    'subject empty list': (o) => (o.subject = []),
    'subject number': (o) => (o.subject = { commonName: 'n.example.com', postalCode: 70112 }),
    'subject number in an array': (o) => (o.subject = { commonName: 'n.example.com', postalCode: [70112] }),
    'subject with a lone surrogate': (o) => (o.subject = { commonName: 'a\uD800b.example.com' }),
    'customOID basicConstraints': (o) =>
      (o.extensions = { ...o.extensions, customOIDs: [{ OID: '2.5.29.19', value: 'critical,DER:30:03:01:01:FF' }] }),
    'customOID subjectKeyIdentifier': (o) =>
      (o.extensions = { ...o.extensions, customOIDs: [{ OID: '2.5.29.14', value: 'DER:04:02:01:02' }] }),
    'customOID subjectAltName': (o) =>
      (o.extensions = {
        ...o.extensions,
        customOIDs: [{ OID: '2.5.29.17', value: 'DER:30:0D:82:0B:78:2E:65:78:61:6D:70:6C:65:2E:63' }],
      }),
    'the same customOID twice': (o) =>
      (o.extensions = {
        ...o.extensions,
        customOIDs: [
          { OID: '1.2.3.4', value: 'ASN1:NULL' },
          { OID: '1.2.3.5', value: 'ASN1:NULL' },
          { OID: '1.2.3.4', value: 'DER:05:00:00' },
        ],
      }),
    'SANs IPv6 with a zone': (o) => (o.extensions = { ...o.extensions, SANs: { IP: ['fe80::1%eth0'] } }),
    'pathlen 1.5': (o) =>
      (o.extensions = { ...o.extensions, basicConstraints: { critical: true, CA: true, pathlen: 1.5 } }),
    'pathlen 1e21': (o) =>
      (o.extensions = { ...o.extensions, basicConstraints: { critical: true, CA: true, pathlen: 1e21 } }),
    'pathlen 2^53': (o) =>
      (o.extensions = { ...o.extensions, basicConstraints: { critical: true, CA: true, pathlen: 2 ** 53 } }),
    'days 0': (o) => {
      delete o.startdate;
      delete o.enddate;
      o.days = 0;
    },
    'days -5': (o) => {
      delete o.startdate;
      delete o.enddate;
      o.days = -5;
    },
    'startdate 1940': (o) => {
      o.startdate = new Date('1940-01-01T00:00:00Z');
      o.enddate = new Date('1941-01-01T00:00:00Z');
    },
  } satisfies Record<string, (o: SignOptions) => unknown>).map(([name, adjust]) => corpusCase({ name, adjust })),
  corpusCase({
    name: 'CSR subject CN first, without a subject',
    csr: { subject: '/CN=www.example.com/O=Example Org/C=US' },
    adjust: (o) => delete o.subject,
  }),
  corpusCase({
    name: 'CSR subject CN first, without a subject, with preserveDN',
    csr: { subject: '/CN=www.example.com/O=Example Org/C=US' },
    adjust: (o) => {
      delete o.subject;
      o.preserveDN = true;
    },
  }),
  corpusCase({
    name: 'CSR subject outside the signing policy, without a subject',
    csr: { subject: '/CN=www.example.com/description=Lab printer' },
    adjust: (o) => delete o.subject,
  }),
  corpusCase({
    name: 'CSR subject with a multi-valued RDN, without a subject',
    csr: { subject: '/CN=www.example.com+OU=Lab/C=US' },
    adjust: (o) => delete o.subject,
  }),
  corpusCase({
    name: 'service SCEP RA',
    csr: { subject: '/C=US' },
    template: false,
    process: { requestoptions: service.scepRA(), template: false },
  }),
];
