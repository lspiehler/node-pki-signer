// Shadow mode on its own; the differential harness also checks it against every corpus case.
import assert from 'node:assert/strict';
import { before, describe, test } from 'node:test';
import { caKeySpecs, createCA, createCSR, type IssuingCA } from '../test/differential/fixtures.ts';
import { X509Certificate } from 'node:crypto';
import { caSignCSR, shadowCASignCSR, type ShadowResult, type SignParams } from './index.ts';

const rsa = caKeySpecs[0]!;

describe('shadowCASignCSR', () => {
  let ca: IssuingCA;
  let other: IssuingCA;
  let csr: string;
  const startdate = new Date(Date.UTC(2026, 0, 1));
  const enddate = new Date(Date.UTC(2027, 0, 1));
  const params = (options: SignParams['options'] = { startdate, enddate }): SignParams => ({
    csr,
    options: { subject: { commonName: 'shadow.example.com' }, ...options },
    ca: ca.cert,
    key: ca.key,
    password: ca.password,
  });
  // what pkiaas passes: no key
  const withoutKey = ({ csr, options, ca }: SignParams) => ({ csr, options, ca });
  // the result without the native TBS, for deepEqual
  const withoutTBS = (result: ShadowResult) => {
    const copy: Partial<ShadowResult> & { tbs?: unknown } = { ...result };
    delete copy.tbs;
    return copy;
  };
  // whether a certificate contains these TBS bytes (its TBS is the first element of the certificate)
  const contains = (pem: string, tbs: Uint8Array) =>
    Buffer.from(new X509Certificate(pem).raw).includes(Buffer.from(tbs));

  before(async () => {
    [ca, other, csr] = await Promise.all([createCA(rsa), createCA(rsa), createCSR(rsa, '/CN=shadow.example.com')]);
  });

  test('matches a certificate issued for the same request', async () => {
    const { data } = await caSignCSR(params());
    const result = await shadowCASignCSR(withoutKey(params()), data);
    assert.deepEqual(withoutTBS(result), {
      signature: 'valid',
      outcome: 'match',
      algorithm: 'sha256WithRSAEncryption',
    });
    // the native TBS is the issued certificate's, byte for byte
    assert.ok(result.outcome === 'match' && contains(data, result.tbs));
  });

  test("takes the certificate's validity when the options have no startdate", async () => {
    const { data } = await caSignCSR(params({ days: 30 }));
    assert.equal((await shadowCASignCSR(withoutKey(params({ days: 30 })), data)).outcome, 'match');
  });

  test('names the fields that differ, without their values', async () => {
    const { data } = await caSignCSR(params({ startdate, enddate, hash: 'sha384' }));
    const result = await shadowCASignCSR(
      withoutKey(params({ startdate, enddate: new Date(Date.UTC(2028, 0, 1)), subject: { commonName: 'other' } })),
      data,
    );
    assert.deepEqual(withoutTBS(result), {
      signature: 'valid',
      outcome: 'differ',
      algorithm: 'sha256WithRSAEncryption',
      fields: ['signature', 'validity', 'subject'],
    });
    // the native TBS is kept, to reproduce the difference
    assert.ok(result.outcome === 'differ' && !contains(data, result.tbs));
  });

  test("differs for another CA's certificate", async () => {
    const { data } = await caSignCSR({ ...params(), ca: other.cert, key: other.key, password: other.password });
    const result = await shadowCASignCSR(withoutKey(params()), data);
    // both test CAs have the same subject, so only the authority key identifier tells them apart,
    // and the signature is the other CA's
    assert.deepEqual(withoutTBS(result), {
      signature: 'invalid',
      outcome: 'differ',
      algorithm: 'sha256WithRSAEncryption',
      fields: ['extension 2.5.29.35'],
    });
  });

  test('reports what the native signer would refuse', async () => {
    const { data } = await caSignCSR(params());
    const refused = await shadowCASignCSR(withoutKey(params({ subject: { countryName: 'USA' } })), data);
    assert.equal(refused.outcome, 'refused');
    assert.ok(refused.step === 'build subject', JSON.stringify(refused));
    const notACert = await shadowCASignCSR(withoutKey(params()), 'not a certificate');
    assert.equal(notACert.outcome, 'refused');
    assert.ok(notACert.step === 'parse issued certificate');
  });

  test('reports what would go to OpenSSL', async () => {
    const { data } = await caSignCSR(params());
    const result = await shadowCASignCSR(withoutKey(params({ startdate, enddate, hash: 'md5' })), data);
    assert.equal(result.outcome, 'unsupported');
    assert.ok(result.step === 'load CA key', JSON.stringify(result));
  });

  test('checks the issued signature whatever the outcome', async () => {
    const { data } = await caSignCSR(params());
    // a flipped bit in the signature value, the last bytes of the certificate
    const der = Buffer.from(new X509Certificate(data).raw);
    der[der.length - 1] = (der[der.length - 1] ?? 0) ^ 0x01;
    const tampered = `-----BEGIN CERTIFICATE-----\n${der.toString('base64')}\n-----END CERTIFICATE-----\n`;
    const result = await shadowCASignCSR(withoutKey(params()), tampered);
    assert.deepEqual([result.outcome, result.signature], ['match', 'invalid']);

    const refused = await shadowCASignCSR(withoutKey(params({ subject: { countryName: 'USA' } })), data);
    assert.deepEqual([refused.outcome, refused.signature], ['refused', 'valid']);
  });

  test("can't check the signature of a certificate or CA that doesn't parse", async () => {
    const { data } = await caSignCSR(params());
    const garbage = await shadowCASignCSR(withoutKey(params()), 'not a certificate');
    assert.equal(garbage.signature, 'unchecked');
    const noCA = await shadowCASignCSR({ ...withoutKey(params()), ca: 'not a CA' }, data);
    assert.deepEqual([noCA.outcome, noCA.signature], ['refused', 'unchecked']);
  });
});
