// Raw DER reading and writing for operations that must copy a structure byte for byte (the final certificate from
// a CT precertificate): ASN.1 libraries re-encode what they parse, which could change an odd but valid encoding.
import { SignerError } from './errors.ts';

/** One DER TLV inside a buffer: its tag byte and where its header, content and end are. */
export interface Tlv {
  tag: number;
  start: number;
  contentStart: number;
  end: number;
}

/** The TLV at `offset`, which must end by `limit`. Definite lengths only, as DER requires. */
export function readTlv(der: Uint8Array, offset: number, limit: number, step: string): Tlv {
  const tag = der[offset];
  const first = der[offset + 1];
  if (tag === undefined || first === undefined || offset + 2 > limit) throw new SignerError(step, 'truncated DER');
  // high tag numbers never occur in the structures this reads
  if ((tag & 0x1f) === 0x1f) throw new SignerError(step, 'unexpected DER tag');
  let length = first;
  let contentStart = offset + 2;
  if (first & 0x80) {
    const count = first & 0x7f;
    // 0x80 is BER's indefinite length; four length bytes are more than any certificate needs
    if (count === 0 || count > 4 || contentStart + count > limit) throw new SignerError(step, 'invalid DER length');
    length = 0;
    for (let i = 0; i < count; i++) length = length * 0x100 + (der[contentStart + i] ?? 0);
    contentStart += count;
  }
  const end = contentStart + length;
  if (end > limit) throw new SignerError(step, 'truncated DER');
  return { tag, start: offset, contentStart, end };
}

/** The TLVs that make up a constructed TLV's content, which must fill it exactly. */
export function readChildren(der: Uint8Array, parent: Tlv, step: string): Tlv[] {
  const children: Tlv[] = [];
  for (let offset = parent.contentStart; offset < parent.end;) {
    const child = readTlv(der, offset, parent.end, step);
    children.push(child);
    offset = child.end;
  }
  return children;
}

/** The bytes of a TLV, header included. */
export const tlvBytes = (der: Uint8Array, tlv: Tlv): Uint8Array => der.subarray(tlv.start, tlv.end);

/** A TLV with the shortest length encoding (X.690 section 10.1). */
export function encodeTlv(tag: number, ...content: Uint8Array[]): Uint8Array {
  const body = Buffer.concat(content);
  const length: number[] = [];
  if (body.length < 0x80) {
    length.push(body.length);
  } else {
    for (let rest = body.length; rest > 0; rest = Math.floor(rest / 0x100)) length.unshift(rest % 0x100);
    length.unshift(0x80 | length.length);
  }
  return new Uint8Array(Buffer.concat([Buffer.from([tag, ...length]), body]));
}
