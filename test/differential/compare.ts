// Compares a candidate certificate with the reference one, field by field and byte for byte. The
// serial number is random in both paths and the signature value can be randomized (ECDSA, ML-DSA),
// so those are checked for form and by verifying, not compared.
import * as asn1js from 'asn1js';
import { X509Certificate } from 'node:crypto';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { openssl } from './openssl.ts';

export interface Difference {
  field: string;
  reference: string;
  candidate: string;
}

type Block = asn1js.AsnType;

function children(block: Block): Block[] {
  const value = (block.valueBlock as { value?: unknown }).value;
  return Array.isArray(value) ? (value as Block[]) : [];
}

function decode(der: Uint8Array): Block {
  const { offset, result } = asn1js.fromBER(der);
  if (offset === -1 || offset !== der.byteLength) throw new Error(`decode certificate: ${result.error}`);
  return result;
}

const hex = (block: Block) => Buffer.from(block.valueBeforeDecodeView).toString('hex');

const tbsFieldNames = ['version', 'serialNumber', 'signature', 'issuer', 'validity', 'subject', 'subjectPublicKeyInfo'];

/** The TBS fields of a certificate by name, extensions by `extension <OID>`, each as hex DER. */
export function certificateFields(pem: string): { fields: Map<string, string>; serial: Uint8Array } {
  const der = new X509Certificate(pem).raw;
  const [tbs, signatureAlgorithm, signatureValue] = children(decode(der));
  if (!tbs || !signatureAlgorithm || !signatureValue) throw new Error('decode certificate: not a Certificate');
  const fields = new Map<string, string>();
  let serial: Uint8Array = new Uint8Array();
  let position = 0;
  for (const field of children(tbs)) {
    const { tagClass, tagNumber } = field.idBlock;
    // the optional context-tagged fields: [0] version, [1]/[2] unique IDs, [3] extensions
    if (tagClass === 3) {
      if (tagNumber === 3) {
        const extensions = children(field)[0];
        if (!extensions) throw new Error('decode certificate: empty extensions');
        const oids: string[] = [];
        for (const extension of children(extensions)) {
          const oid = (children(extension)[0] as asn1js.ObjectIdentifier).valueBlock.toString();
          oids.push(oid);
          fields.set(`extension ${oid}`, hex(extension));
        }
        fields.set('extension order', oids.join(' '));
      } else {
        fields.set(tagNumber === 0 ? 'version' : `[${tagNumber}]`, hex(field));
        if (tagNumber === 0) position = 1;
      }
      continue;
    }
    const name = tbsFieldNames[position++] ?? `field ${position}`;
    if (name === 'serialNumber') {
      serial = (field as asn1js.Integer).valueBlock.valueHexView;
    } else {
      fields.set(name, hex(field));
    }
  }
  fields.set('signatureAlgorithm', hex(signatureAlgorithm));
  if (fields.get('signatureAlgorithm') !== fields.get('signature')) {
    throw new Error('decode certificate: signatureAlgorithm differs from the TBS signature field');
  }
  return { fields, serial };
}

/** RFC 5280 4.1.2.2: a positive INTEGER of at most 20 octets, minimally encoded. */
export function serialProblem(serial: Uint8Array): string | undefined {
  if (serial.length === 0) return 'empty';
  if (serial.length > 20) return `${serial.length} octets`;
  if ((serial[0] ?? 0) & 0x80) return 'negative';
  if (serial.length > 1 && serial[0] === 0 && !((serial[1] ?? 0) & 0x80)) return 'not minimally encoded';
  if (serial.every((b) => b === 0)) return 'zero';
  return undefined;
}

export function compareCertificates(reference: string, candidate: string): Difference[] {
  const ref = certificateFields(reference);
  const cand = certificateFields(candidate);
  const differences: Difference[] = [];
  for (const field of new Set([...ref.fields.keys(), ...cand.fields.keys()])) {
    const r = ref.fields.get(field) ?? '(absent)';
    const c = cand.fields.get(field) ?? '(absent)';
    if (r !== c) differences.push({ field, reference: r, candidate: c });
  }
  const problem = serialProblem(cand.serial);
  if (problem) differences.push({ field: 'serialNumber', reference: 'valid', candidate: problem });
  return differences;
}

async function withPEMs<T>(files: Record<string, string>, run: (dir: string) => Promise<T>): Promise<T> {
  const dir = await mkdtemp(join(tmpdir(), 'pki-signer-compare-'));
  try {
    await Promise.all(Object.entries(files).map(([name, data]) => writeFile(join(dir, name), data)));
    return await run(dir);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

/**
 * `openssl verify` against the issuing CA; resolves to undefined when it verifies, else the error.
 * `precertificate` allows the critical CT poison extension, which openssl doesn't know.
 */
export function opensslVerify(cert: string, ca: string, precertificate = false): Promise<string | undefined> {
  return withPEMs({ 'ca.pem': ca, 'cert.pem': cert }, (dir) =>
    openssl([
      'verify',
      ...(precertificate ? ['-ignore_critical'] : []),
      '-CAfile',
      join(dir, 'ca.pem'),
      join(dir, 'cert.pem'),
    ]).then(
      () => undefined,
      (err: unknown) => String(err),
    ),
  );
}

/** `openssl x509 -text` without the serial number and signature value, which differ by design. */
export async function certificateText(cert: string): Promise<string[]> {
  const text = await openssl(['x509', '-noout', '-text', '-nameopt', 'utf8'], cert);
  const lines: string[] = [];
  let skipping = false;
  for (const line of text.split('\n')) {
    const indent = line.length - line.trimStart().length;
    if (/^\s*(Serial Number|Signature Value):/.test(line)) {
      skipping = true;
      // a short serial number is printed on the same line
      continue;
    }
    if (skipping && indent >= 8 && /^[\s0-9a-f:]+$/.test(line)) continue;
    skipping = false;
    lines.push(line);
  }
  return lines;
}

/** Lines that only one side's `openssl x509 -text` has, prefixed - (reference) and + (candidate). */
export async function textDifferences(reference: string, candidate: string): Promise<string[]> {
  const [ref, cand] = await Promise.all([certificateText(reference), certificateText(candidate)]);
  const refSet = new Set(ref);
  const candSet = new Set(cand);
  return [
    ...ref.filter((l) => !candSet.has(l)).map((l) => `- ${l}`),
    ...cand.filter((l) => !refSet.has(l)).map((l) => `+ ${l}`),
  ];
}
