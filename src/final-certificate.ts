// The final certificate for a CT precertificate (RFC 6962 section 3.1, ADR 0006): the precertificate's own TBS with
// the poison extension swapped for the logs' SCT list, signed again. Every other byte is copied, so the SCTs, which
// the logs signed over the precertificate's TBS minus the poison, verify in the final certificate. Building it again
// from the CSR would draw a new serial and new dates.
import { AsnConvert } from '@peculiar/asn1-schema';
import { AlgorithmIdentifier, Certificate, Extensions } from '@peculiar/asn1-x509';
import { X509Certificate } from 'node:crypto';
import { signatureAlgorithm, signatureAlgorithmName, signatureHash } from './algorithms.ts';
import { derToPEM, equal, pemToDER, signChecked } from './ca-sign-csr.ts';
import { encodeTlv, readChildren, readTlv, tlvBytes, type Tlv } from './der.ts';
import { allowlisted } from './allowlist.ts';
import { SignerError, UnsupportedError } from './errors.ts';
import { selectKey, type KeySettings } from './keys.ts';
import { opensslKey } from './openssl-key.ts';
import type { SignParams } from './options.ts';
import type { SigningKey } from './signing-key.ts';

/**
 * Signs the final certificate's TBS outside the library, for a caller that must sign with OpenSSL in a way this library
 * doesn't: pkiaas with native signing off, through node-openssl-cert2's x509.signTBS, which hands OpenSSL the key in a
 * temp file. This library never writes a key to a file (ADR 0003), so that stays in node-openssl-cert2 (ADR 0006).
 */
export interface FinalCertificateSigner {
  /** who signs, for the result's `backend`, e.g. 'node-openssl-cert2'; never 'software' */
  backend: string;
  /**
   * The signature value over `tbs` with the CA's key, as it goes into the BIT STRING (DER for ECDSA). `name` is the
   * precertificate's signature algorithm, e.g. 'ecdsa-with-SHA256'; `hash` its digest, e.g. 'sha256', or undefined for
   * algorithms that sign the data itself (ML-DSA, SLH-DSA, Ed25519).
   */
  sign(tbs: Uint8Array, algorithm: { name: string; hash: string | undefined }): Promise<Uint8Array>;
}

/** The precertificate, its SCTs, and the CA key that signed it, in the key sources SignParams has. */
export interface FinalCertificateParams extends Pick<SignParams, 'ca' | 'password' | 'pkcs11' | 'kms'> {
  /** the precertificate the CT logs answered, PEM */
  precertificate: string;
  /**
   * the SignedCertificateTimestampList extension's value: the DER OCTET STRING around the TLS-encoded SCT list
   * (RFC 6962 section 3.3), which goes into the extension's extnValue as it is
   */
  sctList: Uint8Array;
  /** issuer private key, PEM, when it isn't on a token or in KMS */
  key?: string;
  /**
   * signs instead of a backend: `key`, `pkcs11` and `kms` are then ignored. Everything else is the same: the
   * precertificate is checked, the final certificate built here, its signature checked against the CA's key before it
   * is used, and the result checked. The allowlist doesn't apply: the caller chose how to sign.
   */
  signer?: FinalCertificateSigner;
}

export interface FinalCertificateResult {
  /** the final certificate, PEM */
  data: string;
  /** its serial number, the precertificate's, upper-case hex */
  serial: string;
  /** the backend that signed it, e.g. 'software', 'openssl', 'pkcs11' */
  backend: string;
}

// the extensions' OIDs as DER TLVs (RFC 6962 section 3.1 and 3.3)
const POISON = '1.3.6.1.4.1.11129.2.4.3';
const SCT_LIST = '1.3.6.1.4.1.11129.2.4.2';
const POISON_OID = Uint8Array.from(Buffer.from('060a2b06010401d679020403', 'hex'));
const SCT_LIST_OID = Uint8Array.from(Buffer.from('060a2b06010401d679020402', 'hex'));
// critical TRUE, and an extnValue that is the DER of NULL
const CRITICAL = Uint8Array.from([0x01, 0x01, 0xff]);
const POISON_VALUE = Uint8Array.from([0x04, 0x02, 0x05, 0x00]);
// version [0] EXPLICIT INTEGER 2 (v3), the only version with extensions
const V3 = Uint8Array.from([0xa0, 0x03, 0x02, 0x01, 0x02]);

const SEQUENCE = 0x30;
const EXTENSIONS = 0xa3;
const OCTET_STRING = 0x04;
const BIT_STRING = 0x03;

/** A certificate's DER cut into the parts the splice needs. */
interface ParsedCertificate {
  der: Uint8Array;
  tbs: Tlv;
  fields: Tlv[];
  signatureAlgorithm: Tlv;
  /** [3] EXPLICIT around the Extensions SEQUENCE, the TBS's last field */
  extensionsField: Tlv;
  extensions: Tlv[];
}

function parseCertificate(der: Uint8Array, step: string): ParsedCertificate {
  const certificate = readTlv(der, 0, der.length, step);
  const parts = readChildren(der, certificate, step);
  const [tbs, signatureAlgorithm, signature] = parts;
  if (certificate.tag !== SEQUENCE || certificate.end !== der.length || parts.length !== 3 || !tbs) {
    throw new SignerError(step, 'not a certificate');
  }
  if (tbs.tag !== SEQUENCE || signatureAlgorithm?.tag !== SEQUENCE || signature?.tag !== BIT_STRING) {
    throw new SignerError(step, 'not a certificate');
  }
  const fields = readChildren(der, tbs, step);
  const extensionsField = fields.at(-1);
  if (!fields[0] || !equal(tlvBytes(der, fields[0]), V3) || extensionsField?.tag !== EXTENSIONS) {
    throw new SignerError(step, 'not a version 3 certificate with extensions');
  }
  const [sequence, ...rest] = readChildren(der, extensionsField, step);
  if (sequence?.tag !== SEQUENCE || rest.length) throw new SignerError(step, 'the extensions are not a SEQUENCE');
  return { der, tbs, fields, signatureAlgorithm, extensionsField, extensions: readChildren(der, sequence, step) };
}

/** The extensions with this OID (a DER TLV): where they are, and their extnID, critical and extnValue TLVs. */
function findExtensions(cert: ParsedCertificate, oid: Uint8Array, step: string): { index: number; parts: Tlv[] }[] {
  return cert.extensions.flatMap((extension, index) => {
    const parts = readChildren(cert.der, extension, step);
    return parts[0] && equal(tlvBytes(cert.der, parts[0]), oid) ? [{ index, parts }] : [];
  });
}

/**
 * The TBS with the extension at `index` replaced (or removed, with null). Only the lengths of the Extensions
 * SEQUENCE, its [3] and the TBS change, written in their shortest form; every other byte is copied.
 */
function replaceExtension(cert: ParsedCertificate, index: number, replacement: Uint8Array | null): Uint8Array {
  const { der, tbs, extensions, extensionsField } = cert;
  const kept = extensions.map((extension, i) => (i === index ? replacement : tlvBytes(der, extension)));
  const sequence = encodeTlv(SEQUENCE, ...kept.filter((bytes) => bytes !== null));
  return encodeTlv(SEQUENCE, der.subarray(tbs.contentStart, extensionsField.start), encodeTlv(EXTENSIONS, sequence));
}

/** Refuses an SCT list that isn't a DER OCTET STRING around a non-empty TLS-encoded list (RFC 6962 section 3.3). */
function checkSctList(sctList: Uint8Array): void {
  const step = 'check SCT list';
  const octets = readTlv(sctList, 0, sctList.length, step);
  const content = sctList.subarray(octets.contentStart);
  if (
    octets.tag !== OCTET_STRING ||
    octets.end !== sctList.length ||
    !equal(encodeTlv(OCTET_STRING, content), sctList)
  ) {
    throw new SignerError(step, 'not a DER OCTET STRING');
  }
  const list = Buffer.from(content);
  if (list.length < 2 || list.readUInt16BE(0) !== list.length - 2)
    throw new SignerError(step, 'the list length is wrong');
  if (list.length === 2) throw new SignerError(step, 'the list is empty');
  for (let offset = 2; offset < list.length;) {
    const length = offset + 2 <= list.length ? list.readUInt16BE(offset) : 0;
    if (length === 0 || offset + 2 + length > list.length) throw new SignerError(step, 'an SCT length is wrong');
    offset += 2 + length;
  }
}

/** The CA certificate's subject, as DER. */
function caSubject(ca: Uint8Array): Uint8Array {
  // any version: only the precertificate must be a v3 certificate with extensions
  const step = 'parse CA certificate';
  const [tbs] = readChildren(ca, readTlv(ca, 0, ca.length, step), step);
  const fields = tbs ? readChildren(ca, tbs, step) : [];
  // version [0], serialNumber, signature, issuer, validity, subject
  const subject = fields[fields[0]?.tag === 0xa0 ? 5 : 4];
  if (!subject) throw new SignerError(step, 'not a certificate');
  return tlvBytes(ca, subject);
}

/** The backends of `backends` (all by default) that sign with openssl: for algorithms forced to OpenSSL. */
export function opensslBackends(backends?: readonly string[]): string[] {
  return (backends ?? ['openssl', 'openssl-pkcs11']).filter((b) => b === 'openssl' || b === 'openssl-pkcs11');
}

/**
 * Builds and signs the final certificate for a precertificate this CA signed. Refuses, with a SignerError naming the
 * step, a precertificate the CA's key didn't sign, one without exactly one critical poison extension or with an SCT
 * list already, and a signature algorithm it can't sign (e.g. RSA-PSS, or ML-DSA on a PKCS#11 token: an
 * UnsupportedError). There is no OpenSSL fallback for the whole operation: an algorithm forced to OpenSSL is signed
 * by the openssl backends. Checks the result before returning it.
 */
export async function signFinalCertificate(
  params: FinalCertificateParams,
  settings: KeySettings = {},
): Promise<FinalCertificateResult> {
  // OpenSSL verifies the very bytes that are spliced: each PEM is decoded once
  const precertDER = pemToDER(params.precertificate, 'CERTIFICATE', 'parse precertificate');
  const caDER = pemToDER(params.ca, 'CERTIFICATE', 'parse CA certificate');
  let precertificate: X509Certificate;
  let ca: X509Certificate;
  try {
    precertificate = new X509Certificate(Buffer.from(precertDER));
  } catch {
    throw new SignerError('parse precertificate', 'not a certificate');
  }
  try {
    ca = new X509Certificate(Buffer.from(caDER));
  } catch {
    throw new SignerError('parse CA certificate', 'not a certificate');
  }
  const precert = parseCertificate(precertDER, 'parse precertificate');
  const { der, fields } = precert;

  // the CA's key signed exactly these bytes, so the final certificate only says what the CA already said
  const step = 'check precertificate';
  if (!fields[3] || !equal(tlvBytes(der, fields[3]), caSubject(caDER))) {
    throw new SignerError(step, "the precertificate's issuer is not the CA");
  }
  if (!precertificate.verify(ca.publicKey)) {
    throw new SignerError('verify precertificate', "the precertificate is not signed by the CA's key");
  }
  // what isn't DER can't become DER by copying it
  checkDER(der, step);
  const algorithmBytes = tlvBytes(der, precert.signatureAlgorithm);
  if (!fields[2] || !equal(tlvBytes(der, fields[2]), algorithmBytes)) {
    throw new SignerError(step, 'the signature algorithms inside and outside the TBS differ');
  }
  const poisons = findExtensions(precert, POISON_OID, step);
  if (poisons.length !== 1 || !poisons[0]) throw new SignerError(step, 'not exactly one poison extension');
  const { index: poison, parts } = poisons[0];
  const [, critical, value, ...extra] = parts;
  if (!critical || !equal(tlvBytes(der, critical), CRITICAL) || !value || extra.length) {
    throw new SignerError(step, 'the poison extension is not critical');
  }
  if (!equal(tlvBytes(der, value), POISON_VALUE)) throw new SignerError(step, 'the poison extension is not NULL');
  if (findExtensions(precert, SCT_LIST_OID, step).length) throw new SignerError(step, 'it has an SCT list already');
  checkSctList(params.sctList);

  // the precertificate's signature algorithm, which the CA's key must sign with
  const oid = AsnConvert.parse(algorithmBytes, AlgorithmIdentifier).algorithm;
  const name = signatureAlgorithmName(oid, 'parse precertificate');
  const hash = signatureHash(name) ?? 'default';
  if (signatureAlgorithm(ca.publicKey, hash) !== name) {
    throw new SignerError('load CA key', `the CA's key doesn't sign ${name}`);
  }
  const key = await finalKey(params, hash, name, ca, settings);
  if (!equal(await key.publicKey(), ca.publicKey.export({ type: 'spki', format: 'der' }))) {
    throw new SignerError('load CA key', "the CA certificate and private key don't match");
  }

  const extension = encodeTlv(SEQUENCE, SCT_LIST_OID, encodeTlv(OCTET_STRING, params.sctList));
  const tbs = replaceExtension(precert, poison, extension);
  const signature = await signChecked(tbs, oid, key, ca.publicKey);
  const final = encodeTlv(SEQUENCE, tbs, algorithmBytes, encodeTlv(BIT_STRING, Uint8Array.of(0), signature));
  checkFinal(precert, poison, final, params.sctList, ca);
  return { data: derToPEM(final, 'CERTIFICATE'), serial: precertificate.serialNumber, backend: key.backend };
}

/**
 * The CA's key for the final certificate. An algorithm forced to OpenSSL is signed by the openssl backends. A Google
 * KMS key the KMS backend can't sign (e.g. EC, or forced to OpenSSL) is signed through its PKCS#11 module with
 * OpenSSL, as node-openssl-cert2 signs its precertificate: there is no whole-operation fallback here.
 */
async function finalKey(
  params: FinalCertificateParams,
  hash: string,
  name: string,
  ca: X509Certificate,
  settings: KeySettings,
): Promise<SigningKey> {
  if (params.signer) return callerKey(params.signer, name, hash, ca);
  const forced = settings.forceOpenSSL?.includes(name);
  const backends = forced ? opensslBackends(settings.backends) : settings.backends;
  try {
    return await selectKey({ ...params, key: params.key ?? '', options: { hash } }, ca.publicKey, {
      ...settings,
      forceOpenSSL: [],
      ...(backends ? { backends } : {}),
    });
  } catch (err) {
    const pkcs11 = params.pkcs11;
    const usable = !backends || backends.includes('openssl-pkcs11');
    if (!(err instanceof UnsupportedError) || !params.kms?.keyVersion || !pkcs11 || !usable) throw err;
    if (!(settings.allowlisted ?? allowlisted)('openssl-pkcs11').has(name)) throw err;
    const publicKey = new Uint8Array(ca.publicKey.export({ type: 'spki', format: 'der' }));
    return opensslKey({ pkcs11 }, name, publicKey, settings.binpath);
  }
}

/**
 * A SigningKey over the caller's signer. Its public key is the CA certificate's, so the key check before signing passes,
 * and signChecked verifies the signature against the CA's key, which only it can catch: a signer named 'software'
 * would skip that check, so it is refused.
 */
function callerKey(signer: FinalCertificateSigner, name: string, hash: string, ca: X509Certificate): SigningKey {
  if (signer.backend === 'software') {
    throw new SignerError('load CA key', "a caller's signer can't be named software");
  }
  const step = `sign with ${signer.backend}`;
  return {
    backend: signer.backend,
    algorithm: name,
    publicKey: () => Promise.resolve(new Uint8Array(ca.publicKey.export({ type: 'spki', format: 'der' }))),
    async sign(tbs) {
      try {
        return await signer.sign(tbs, { name, hash: hash === 'default' ? undefined : hash });
      } catch (err) {
        if (err instanceof SignerError) throw err;
        throw new SignerError(step, err instanceof Error ? err.message : String(err).trim());
      }
    },
  };
}

/** Refuses a certificate that isn't DER: re-encoding what @peculiar parses must give the same bytes. */
function checkDER(der: Uint8Array, step: string): void {
  let reencoded: ArrayBuffer;
  try {
    const parsed = AsnConvert.parse(der, Certificate);
    reencoded = AsnConvert.serialize(
      new Certificate({
        tbsCertificate: parsed.tbsCertificate,
        signatureAlgorithm: parsed.signatureAlgorithm,
        signatureValue: parsed.signatureValue,
      }),
    );
  } catch (err) {
    throw new SignerError(step, `it doesn't parse: ${err instanceof Error ? err.message : String(err)}`);
  }
  if (!equal(reencoded, der)) throw new SignerError(step, 'it is not DER');
}

/** The TBS without the extension with this OID, as @peculiar parses and re-encodes it. */
function tbsWithout(der: Uint8Array, oid: string, step: string): ArrayBuffer {
  try {
    const { tbsCertificate } = AsnConvert.parse(der, Certificate);
    tbsCertificate.extensions = new Extensions(tbsCertificate.extensions?.filter((e) => e.extnID !== oid));
    return AsnConvert.serialize(tbsCertificate);
  } catch (err) {
    throw new SignerError(step, `it doesn't parse: ${err instanceof Error ? err.message : String(err)}`);
  }
}

/** Checks the final certificate before anyone sees it, each check independent of how it was built. */
function checkFinal(
  precert: ParsedCertificate,
  poison: number,
  der: Uint8Array,
  sctList: Uint8Array,
  ca: X509Certificate,
) {
  const step = 'check final certificate';
  const final = parseCertificate(der, step);
  // the SCT list sits where the poison was, with exactly the bytes the logs' answers made
  const [sct, ...more] = findExtensions(final, SCT_LIST_OID, step);
  const sctIndex = sct?.index;
  const [, value, ...extra] = sct?.parts ?? [];
  if (
    sctIndex !== poison ||
    more.length ||
    extra.length ||
    !value ||
    !equal(der.subarray(value.contentStart, value.end), sctList)
  ) {
    throw new SignerError(step, 'the SCT list is not where the poison was');
  }
  // the TBS without the SCT list is the precertificate's TBS without the poison, byte for byte (RFC 6962 section 3.2),
  // as the raw bytes browsers and CT verifiers strip, and as @peculiar (not the splice code) reads them
  if (
    !equal(replaceExtension(final, sctIndex, null), replaceExtension(precert, poison, null)) ||
    !equal(tbsWithout(der, SCT_LIST, step), tbsWithout(precert.der, POISON, step))
  ) {
    throw new SignerError(step, "the TBS differs from the precertificate's");
  }
  checkDER(der, step);
  // OpenSSL reads it and the CA's key verifies it
  let x509: X509Certificate;
  try {
    x509 = new X509Certificate(der);
  } catch {
    throw new SignerError(step, "OpenSSL can't read it");
  }
  if (!x509.verify(ca.publicKey)) throw new SignerError(step, "the signature doesn't verify with the CA's key");
}
