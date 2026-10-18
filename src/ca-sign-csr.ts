// Signs a CSR natively: the same certificate `openssl ca` issues through node-openssl-cert2's
// x509.CASignCSR (ADR 0001), apart from the intended differences in ADR 0002.
import { CertificationRequest } from '@peculiar/asn1-csr';
import { AsnConvert, OctetString } from '@peculiar/asn1-schema';
import {
  AuthorityKeyIdentifier,
  Certificate,
  Extension,
  Extensions,
  KeyIdentifier,
  SubjectKeyIdentifier,
  TBSCertificate,
  Validity,
  Version,
  id_ce_authorityKeyIdentifier,
  id_ce_subjectKeyIdentifier,
} from '@peculiar/asn1-x509';
import * as asn1js from 'asn1js';
import { X509Certificate, createHash, createPublicKey, randomBytes, verify, type KeyObject } from 'node:crypto';
import { promisify } from 'node:util';
import { algorithmIdentifier, verifyHash } from './algorithms.ts';
import { SignerError, UnsupportedError } from './errors.ts';
import { buildExtensions } from './extensions.ts';
import { selectKey, type KeySettings } from './keys.ts';
import type { SignParams, SignResult } from './options.ts';
import type { SigningKey } from './signing-key.ts';
import { buildSubject } from './subject.ts';

const verifyAsync = promisify(verify);

const day = 24 * 60 * 60 * 1000;

function pemToDER(pem: string, label: string, step: string): Uint8Array {
  const match = new RegExp(`-----BEGIN ${label}-----([^-]+)-----END ${label}-----`).exec(pem);
  if (!match?.[1]) throw new SignerError(step, `no ${label} PEM`);
  return new Uint8Array(Buffer.from(match[1], 'base64'));
}

function derToPEM(der: ArrayBuffer, label: string): string {
  const lines =
    Buffer.from(der)
      .toString('base64')
      .match(/.{1,64}/g) ?? [];
  return `-----BEGIN ${label}-----\n${lines.join('\n')}\n-----END ${label}-----\n`;
}

const asBytes = (a: ArrayBuffer | Uint8Array) => (a instanceof Uint8Array ? a : new Uint8Array(a));
const equal = (a: ArrayBuffer | Uint8Array, b: ArrayBuffer | Uint8Array) => Buffer.from(asBytes(a)).equals(asBytes(b));

async function parseCSR(pem: string) {
  let csr: CertificationRequest;
  try {
    csr = AsnConvert.parse(pemToDER(pem, '(?:NEW )?CERTIFICATE REQUEST', 'parse CSR'), CertificationRequest);
  } catch (err) {
    if (err instanceof SignerError) throw err;
    throw new SignerError('parse CSR', 'not a certificate request');
  }
  const info = csr.certificationRequestInfo;
  const raw = csr.certificationRequestInfoRaw;
  if (!raw) throw new SignerError('parse CSR', 'no certification request info');
  // `openssl ca` refuses a request whose self-signature doesn't verify
  const hash = verifyHash(csr.signatureAlgorithm.algorithm);
  let verified: boolean;
  try {
    const publicKey = createPublicKey({
      key: Buffer.from(AsnConvert.serialize(info.subjectPKInfo)),
      format: 'der',
      type: 'spki',
    });
    verified = await verifyAsync(hash, new Uint8Array(raw), publicKey, new Uint8Array(csr.signature));
  } catch (err) {
    throw new UnsupportedError('verify CSR signature', err instanceof Error ? err.message : String(err));
  }
  if (!verified) throw new SignerError('verify CSR signature', 'the signature does not match the request');
  return info;
}

// the issuer's subject, which must re-encode to its exact bytes, and its key identifier
function parseIssuer(pem: string) {
  let x509: X509Certificate;
  let certificate: Certificate;
  try {
    x509 = new X509Certificate(pem);
    certificate = AsnConvert.parse(x509.raw, Certificate);
  } catch {
    throw new SignerError('parse CA certificate', 'not a certificate');
  }
  const tbs = certificate.tbsCertificate;
  const children = (block: asn1js.AsnType | undefined) => (block?.valueBlock as { value?: asn1js.AsnType[] }).value;
  const tbsFields = children(children(asn1js.fromBER(new Uint8Array(x509.raw)).result)?.[0]);
  // version [0], serialNumber, signature, issuer, validity, subject
  const subjectRaw = tbsFields?.[tbsFields[0]?.idBlock.tagClass === 3 ? 5 : 4]?.valueBeforeDecodeView;
  if (!subjectRaw || !equal(AsnConvert.serialize(tbs.subject), subjectRaw)) {
    throw new UnsupportedError('parse CA certificate', "the CA's subject doesn't re-encode exactly");
  }
  const ski = tbs.extensions?.find((e) => e.extnID === id_ce_subjectKeyIdentifier);
  // `authorityKeyIdentifier = keyid:always` needs the CA's own key identifier
  if (!ski) throw new UnsupportedError('parse CA certificate', 'the CA has no subject key identifier');
  const keyIdentifier = AsnConvert.parse(ski.extnValue, SubjectKeyIdentifier);
  return { subject: tbs.subject, keyIdentifier, publicKey: x509.publicKey };
}

function date(value: unknown, name: string): Date {
  const parsed = value === undefined ? new Date() : new Date(value as string);
  // GeneralizedTime has four-digit years, and `openssl ca` refuses dates it can't write
  const year = parsed.getUTCFullYear();
  if (Number.isNaN(year) || year < 0 || year > 9999) throw new SignerError('build TBS', `invalid ${name}`);
  // OpenSSL takes whole seconds, always as UTC (ADR 0002)
  return new Date(Math.floor(parsed.getTime() / 1000) * 1000);
}

/** A random positive serial of up to 159 bits, as `openssl ca -create_serial` draws it: DER content and hex. */
function randomSerial(): { content: ArrayBuffer; hex: string } {
  for (;;) {
    const bytes = randomBytes(20);
    bytes[0] = (bytes[0] ?? 0) & 0x7f;
    const start = bytes.findIndex((b) => b !== 0);
    if (start < 0) continue;
    const magnitude = bytes.subarray(start);
    const content = (magnitude[0] ?? 0) & 0x80 ? Buffer.concat([Buffer.from([0]), magnitude]) : magnitude;
    return { content: new Uint8Array(content).buffer, hex: magnitude.toString('hex').toUpperCase() };
  }
}

/** Signs a TBS certificate with `key` and returns the certificate DER. */
async function signTBS(tbs: TBSCertificate, key: SigningKey, issuerKey: KeyObject): Promise<ArrayBuffer> {
  const tbsDER = AsnConvert.serialize(tbs);
  const signature = await key.sign(new Uint8Array(tbsDER));
  // a token, KMS or openssl signs with a key we never see, so check it's the CA's (ADR 0003)
  if (key.backend !== 'software') {
    let verified: boolean;
    try {
      verified = await verifyAsync(verifyHash(tbs.signature.algorithm), new Uint8Array(tbsDER), issuerKey, signature);
    } catch (err) {
      throw new SignerError('verify signature', err instanceof Error ? err.message : String(err));
    }
    if (!verified) {
      throw new SignerError('verify signature', `the ${key.backend} key doesn't match the CA certificate`);
    }
  }
  return AsnConvert.serialize(
    new Certificate({
      tbsCertificate: tbs,
      signatureAlgorithm: tbs.signature,
      signatureValue: new Uint8Array(signature).buffer,
    }),
  );
}

export type NativeSettings = KeySettings;

type CSRInfo = Awaited<ReturnType<typeof parseCSR>>;
type Issuer = ReturnType<typeof parseIssuer>;

/** Parses and checks the CSR and the CA certificate. */
export async function parseRequest(params: SignParams): Promise<{ info: CSRInfo; issuer: Issuer }> {
  return { info: await parseCSR(params.csr), issuer: parseIssuer(params.ca) };
}

/** The validity from the options: startdate to enddate, or `days` from now without a startdate. */
export function validity(options: SignParams['options']): Validity {
  const startdate = options.startdate ? date(options.startdate, 'startdate') : date(undefined, 'startdate');
  const enddate = options.startdate
    ? date(options.enddate, 'enddate')
    : date(startdate.getTime() + (options.days ?? 365) * day, 'enddate');
  return new Validity({ notBefore: startdate, notAfter: enddate });
}

// node-openssl-cert2 refuses a control character anywhere in the subject or extensions (a line break would
// start a new openssl.cnf line); returns the path of the first string that has one, like its message
function findControlCharacter(value: unknown, path: string): string | undefined {
  // eslint-disable-next-line no-control-regex
  if (typeof value === 'string') return /[\x00-\x1f\x7f]/.test(value) ? path : undefined;
  if (value && typeof value === 'object' && !(value instanceof Date)) {
    for (const [key, item] of Object.entries(value)) {
      const found = findControlCharacter(key, path) ?? findControlCharacter(item, `${path}.${key}`);
      if (found) return found;
    }
  }
  return undefined;
}

/** The TBS certificate `openssl ca` would build for this request, with the given serial and validity. */
export function buildTBS(
  params: SignParams,
  { info, issuer }: { info: CSRInfo; issuer: Issuer },
  algorithm: string,
  serial: ArrayBuffer,
  dates: Validity,
): TBSCertificate {
  const options = params.options;
  const invalid = findControlCharacter({ subject: options.subject, extensions: options.extensions }, 'options');
  if (invalid) throw new SignerError('build TBS', `control character in ${invalid}`);
  const spki = info.subjectPKInfo;
  const subjectKeyIdentifier = createHash('sha1').update(new Uint8Array(spki.subjectPublicKey)).digest();
  const extensions = [
    new Extension({
      extnID: id_ce_subjectKeyIdentifier,
      critical: false,
      extnValue: new OctetString(AsnConvert.serialize(new SubjectKeyIdentifier(subjectKeyIdentifier))),
    }),
    new Extension({
      extnID: id_ce_authorityKeyIdentifier,
      critical: false,
      extnValue: new OctetString(
        AsnConvert.serialize(new AuthorityKeyIdentifier({ keyIdentifier: new KeyIdentifier(issuer.keyIdentifier) })),
      ),
    }),
    ...buildExtensions(options.extensions),
  ];

  try {
    return new TBSCertificate({
      version: Version.v3,
      serialNumber: serial,
      signature: algorithmIdentifier(algorithm),
      issuer: issuer.subject,
      validity: dates,
      // the subject is forced from the options when they have one (`-subj`); the CSR's extensions are never copied
      subject: Object.hasOwn(options, 'subject') ? buildSubject(options.subject) : info.subject,
      subjectPublicKeyInfo: spki,
      extensions: new Extensions(extensions),
    });
  } catch (err) {
    if (err instanceof SignerError) throw err;
    throw new SignerError('build TBS', err instanceof Error ? err.message : String(err));
  }
}

/**
 * Signs a CSR with a CA, taking the same parameters as node-openssl-cert2's x509.CASignCSR and
 * returning its `data` and `serial`. Throws UnsupportedError for what must go to OpenSSL instead.
 */
export async function caSignCSR(params: SignParams, settings: NativeSettings = {}): Promise<SignResult> {
  const request = await parseRequest(params);
  const { issuer } = request;
  const key = await selectKey(params, issuer.publicKey, settings);
  const caPublicKey = issuer.publicKey.export({ type: 'spki', format: 'der' });
  if (!equal(await key.publicKey(), caPublicKey)) {
    throw new SignerError('load CA key', "the CA certificate and private key don't match");
  }
  const dates = validity(params.options);
  const serial = randomSerial();
  const tbs = buildTBS(params, request, key.algorithm, serial.content, dates);
  return { data: derToPEM(await signTBS(tbs, key, issuer.publicKey), 'CERTIFICATE'), serial: serial.hex };
}
