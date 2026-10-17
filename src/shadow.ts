// Shadow mode (ADR 0004): checks a certificate that node-openssl-cert2 (or an IoT HSM agent) issued
// against the TBS the native signer would build for the same request, without signing anything.
import { AsnConvert } from '@peculiar/asn1-schema';
import { Certificate } from '@peculiar/asn1-x509';
import { X509Certificate } from 'node:crypto';
import { signatureAlgorithm } from './algorithms.ts';
import { buildTBS, parseRequest, validity } from './ca-sign-csr.ts';
import { SignerError, UnsupportedError } from './errors.ts';
import type { SignParams } from './options.ts';
import { children, decode, tbsFields } from './tbs-fields.ts';

/**
 * Whether the issued certificate's signature verifies with the CA certificate's public key;
 * `unchecked` when either certificate can't be parsed or the key type can't verify.
 */
export type IssuedSignature = 'valid' | 'invalid' | 'unchecked';

/**
 * What the native signer would have done: `match` built the same TBS byte for byte, `differ` lists
 * the TBS fields that differ (names only, never values), `unsupported` would have gone to OpenSSL and
 * `refused` would have refused the request. `algorithm` is the CA's signature algorithm, when known.
 * `tbs` is the TBS the native signer built (DER), to keep for reproducing a difference. `signature`
 * checks the issued certificate itself, whatever the outcome.
 */
export type ShadowResult = { signature: IssuedSignature } & (
  | { outcome: 'match'; algorithm: string; tbs: Uint8Array }
  | { outcome: 'differ'; algorithm: string; fields: string[]; tbs: Uint8Array }
  | { outcome: 'unsupported' | 'refused'; algorithm?: string; step: string; reason: string }
);

const message = (err: unknown) => (err instanceof Error ? err.message : String(err));

function issuedSignature(certificate: string, ca: string): IssuedSignature {
  try {
    return new X509Certificate(certificate).verify(new X509Certificate(ca).publicKey) ? 'valid' : 'invalid';
  } catch {
    return 'unchecked';
  }
}

/**
 * Compares `certificate` (PEM), issued for `params`, with the TBS the native signer builds for
 * `params` using the certificate's serial number, and its validity when the options give no
 * startdate. Needs no private key: `params.key`, `pkcs11` and `kms` are ignored.
 */
export async function shadowCASignCSR(
  params: Pick<SignParams, 'csr' | 'options' | 'ca'>,
  certificate: string,
): Promise<ShadowResult> {
  const signature = issuedSignature(certificate, params.ca);
  let algorithm: string | undefined;
  try {
    let issued: { tbs: ReturnType<typeof tbsFields>; certificate: Certificate };
    try {
      const der = new Uint8Array(new X509Certificate(certificate).raw);
      const tbs = children(decode(der))[0];
      if (!tbs) throw new Error('not a Certificate');
      issued = { tbs: tbsFields(tbs), certificate: AsnConvert.parse(der, Certificate) };
    } catch (err) {
      throw new SignerError('parse issued certificate', message(err));
    }
    const request = await parseRequest({ ...params, key: '' });
    algorithm = signatureAlgorithm(request.issuer.publicKey, params.options.hash ?? 'sha256');
    const dates = params.options.startdate ? validity(params.options) : issued.certificate.tbsCertificate.validity;
    const tbs = buildTBS({ ...params, key: '' }, request, algorithm, new Uint8Array(issued.tbs.serial).buffer, dates);
    const der = new Uint8Array(AsnConvert.serialize(tbs));
    const native = tbsFields(decode(der)).fields;
    const fields = [...new Set([...native.keys(), ...issued.tbs.fields.keys()])].filter(
      (field) => native.get(field) !== issued.tbs.fields.get(field),
    );
    return fields.length
      ? { signature, outcome: 'differ', algorithm, fields, tbs: der }
      : { signature, outcome: 'match', algorithm, tbs: der };
  } catch (err) {
    const step = err instanceof SignerError ? err.step : 'native signer';
    const reason = err instanceof SignerError ? err.message : `native signer: unexpected error: ${message(err)}`;
    const outcome = err instanceof UnsupportedError || !(err instanceof SignerError) ? 'unsupported' : 'refused';
    return { signature, outcome, ...(algorithm ? { algorithm } : {}), step, reason };
  }
}
