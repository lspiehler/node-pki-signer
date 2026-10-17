// The native signer on its own: what the differential harness can't show, because it pins TZ=UTC and
// only compares certificates both paths issue.
import assert from 'node:assert/strict';
import { X509Certificate } from 'node:crypto';
import { before, describe, test } from 'node:test';
import { caKeySpecs, createCA, createCSR, type IssuingCA } from '../test/differential/fixtures.ts';
import { caSignCSR, SignerError, UnsupportedError, type SignParams } from './index.ts';

// ADR 0002: validity dates must not depend on the host's time zone
process.env.TZ = 'Asia/Tokyo';

const rsa = caKeySpecs[0]!;

describe('caSignCSR', () => {
  let ca: IssuingCA;
  let other: IssuingCA;
  let csr: string;
  const params = (options: SignParams['options'] = {}): SignParams => ({
    csr,
    options: { subject: { commonName: 'unit.example.com' }, ...options },
    ca: ca.cert,
    key: ca.key,
    password: ca.password,
  });
  const failsAt =
    (step: string, type: typeof SignerError = SignerError) =>
    (err: unknown) => {
      assert.ok(err instanceof type, String(err));
      assert.equal(err.step, step);
      return true;
    };

  before(async () => {
    [ca, other, csr] = await Promise.all([createCA(rsa), createCA(rsa), createCSR(rsa, '/CN=unit.example.com')]);
  });

  test('issues startdate and enddate as UTC in any time zone', async () => {
    const startdate = new Date(Date.UTC(2026, 0, 1, 0, 0, 0));
    const enddate = new Date(Date.UTC(2027, 0, 1, 12, 30, 45));
    const cert = new X509Certificate((await caSignCSR(params({ startdate, enddate }))).data);
    assert.equal(cert.validFromDate.toISOString(), startdate.toISOString());
    assert.equal(cert.validToDate.toISOString(), enddate.toISOString());
  });

  test('issues days from now without a startdate', async () => {
    const before = Math.floor(Date.now() / 1000) * 1000;
    const cert = new X509Certificate((await caSignCSR(params({ days: 30 }))).data);
    const from = cert.validFromDate.getTime();
    assert.ok(from >= before && from <= Date.now(), cert.validFrom);
    assert.equal(cert.validToDate.getTime() - from, 30 * 24 * 60 * 60 * 1000);
  });

  test('returns the serial number as upper-case hex', async () => {
    const result = await caSignCSR(params());
    assert.equal(result.serial, new X509Certificate(result.data).serialNumber);
    assert.match(result.serial, /^[0-9A-F]+$/);
  });

  test('refuses a key that does not match the CA certificate', async () => {
    await assert.rejects(caSignCSR({ ...params(), key: other.key, password: other.password }), failsAt('load CA key'));
  });

  test('refuses a wrong passphrase without repeating it', async () => {
    await assert.rejects(caSignCSR({ ...params(), password: 'wrong-passphrase' }), (err: unknown) => {
      failsAt('load CA key')(err);
      assert.ok(!String(err).includes('wrong-passphrase'));
      return true;
    });
  });

  test('refuses a CSR whose signature does not verify', async () => {
    const der = Buffer.from(csr.replace(/-----[^-]+-----|\s/g, ''), 'base64');
    der[der.length - 1] = (der[der.length - 1] ?? 0) ^ 0xff;
    const lines = der.toString('base64').match(/.{1,64}/g) ?? [];
    const tampered = `-----BEGIN CERTIFICATE REQUEST-----\n${lines.join('\n')}\n-----END CERTIFICATE REQUEST-----\n`;
    await assert.rejects(caSignCSR({ ...params(), csr: tampered }), failsAt('verify CSR signature'));
  });

  test('refuses subject attributes node-openssl-cert2 does not know', async () => {
    await assert.rejects(caSignCSR(params({ subject: { undefined: 'b' } })), failsAt('build subject'));
  });

  test('refuses subject values OpenSSL would refuse', async () => {
    await assert.rejects(caSignCSR(params({ subject: { countryName: 'USA' } })), failsAt('build subject'));
    await assert.rejects(caSignCSR(params({ subject: { commonName: 'a'.repeat(65) } })), failsAt('build subject'));
  });

  test('refuses unknown extensions', async () => {
    await assert.rejects(caSignCSR(params({ extensions: { nameConstraints: {} } })), failsAt('build extensions'));
  });

  test('leaves PKCS#11 keys to OpenSSL without PKCS#11 sessions', async () => {
    await assert.rejects(
      caSignCSR({ ...params(), pkcs11: { uri: 'pkcs11:', modulePath: '/nonexistent.so' } }, { backends: ['pkcs11'] }),
      failsAt('load CA key', UnsupportedError),
    );
  });

  test('leaves libkmsp11 keys without a key version to OpenSSL', async () => {
    await assert.rejects(
      caSignCSR({ ...params(), pkcs11: { uri: 'pkcs11:object=k', modulePath: '/usr/lib/kms/libkmsp11.so' } }),
      failsAt('load CA key', UnsupportedError),
    );
  });
});
