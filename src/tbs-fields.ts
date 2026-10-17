// Splits a to-be-signed certificate into its fields as DER, so two certificates can be compared field
// by field and byte for byte (the differential harness and shadow mode).
import * as asn1js from 'asn1js';

type Block = asn1js.AsnType;

export function children(block: Block): Block[] {
  const value = (block.valueBlock as { value?: unknown }).value;
  return Array.isArray(value) ? (value as Block[]) : [];
}

export function decode(der: Uint8Array): Block {
  const { offset, result } = asn1js.fromBER(der);
  if (offset === -1 || offset !== der.byteLength) throw new Error(`decode certificate: ${result.error}`);
  return result;
}

export const hex = (block: Block) => Buffer.from(block.valueBeforeDecodeView).toString('hex');

const tbsFieldNames = ['version', 'serialNumber', 'signature', 'issuer', 'validity', 'subject', 'subjectPublicKeyInfo'];

/**
 * A TBSCertificate's fields by name, extensions by `extension <OID>` plus their `extension order`,
 * each as hex DER; the serial number as its INTEGER content instead.
 */
export function tbsFields(tbs: Block): { fields: Map<string, string>; serial: Uint8Array } {
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
  return { fields, serial };
}
