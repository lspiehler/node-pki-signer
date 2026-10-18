// createSigner: when it signs natively, when it falls back to node-openssl-cert2, and the
// callback form pkiaas and the IoT HSM agent call.
import assert from 'node:assert/strict';
import { X509Certificate } from 'node:crypto';
import { before, describe, test } from 'node:test';
import { caKeySpecs, createCA, createCSR, type IssuingCA } from '../test/differential/fixtures.ts';
import { openssl } from '../test/differential/openssl.ts';
import { createSigner, SignerError, type CASignCSRResult, type Fallback, type SignParams } from './index.ts';

const rsa = caKeySpecs[0]!;
const ec = caKeySpecs.find((s) => s.name === 'EC-P256')!;

describe('createSigner', () => {
  let rsaCA: IssuingCA;
  let ecCA: IssuingCA;
  let csr: string;
  const params = (ca: IssuingCA, options: SignParams['options'] = {}): SignParams => ({
    csr,
    options: { subject: { commonName: 'signer.example.com' }, ...options },
    ca: ca.cert,
    key: ca.key,
    password: ca.password,
  });
  const signer = (settings: Parameters<typeof createSigner>[0] = {}) => {
    const fallbacks: Fallback[] = [];
    return { fallbacks, ...createSigner({ ...settings, onFallback: (f) => fallbacks.push(f) }) };
  };
  const issuedBy = (pem: string, ca: IssuingCA) =>
    new X509Certificate(pem).verify(new X509Certificate(ca.cert).publicKey);
  const callback = (s: ReturnType<typeof signer>, p: SignParams) =>
    new Promise<{ err: false | string | Error; result: CASignCSRResult | false }>((resolve) => {
      s.x509.CASignCSR(p, (err, result) => {
        resolve({ err, result });
      });
    });

  before(async () => {
    [rsaCA, ecCA, csr] = await Promise.all([createCA(rsa), createCA(ec), createCSR(rsa, '/CN=signer.example.com')]);
  });

  test('signs allowlisted algorithms natively', async () => {
    const s = signer();
    const result = await s.caSignCSR(params(rsaCA));
    assert.equal(result.signedBy, 'native');
    assert.ok(issuedBy(result.data, rsaCA));
    assert.equal(result.serial, new X509Certificate(result.data).serialNumber);
    assert.deepEqual(s.fallbacks, []);
  });

  test('falls back for everything when forced', async () => {
    const s = signer({ forceOpenSSL: true });
    const result = await s.caSignCSR(params(rsaCA));
    assert.equal(result.signedBy, 'openssl');
    assert.ok(issuedBy(result.data, rsaCA));
    assert.equal(result.serial, new X509Certificate(result.data).serialNumber);
    assert.deepEqual(
      s.fallbacks.map((f) => [f.operation, f.step]),
      [['CASignCSR', 'check allowlist']],
    );
  });

  test('falls back only for the algorithms forced to OpenSSL', async () => {
    const s = signer({ forceOpenSSL: ['sha256WithRSAEncryption'] });
    assert.equal((await s.caSignCSR(params(rsaCA))).signedBy, 'openssl');
    assert.equal((await s.caSignCSR(params(ecCA))).signedBy, 'native');
    assert.deepEqual(
      s.fallbacks.map((f) => f.reason),
      ['check allowlist: sha256WithRSAEncryption is set to sign with OpenSSL'],
    );
  });

  test('falls back for what the native signer does not support', async () => {
    const s = signer();
    // OpenSSL reads digest names case-insensitively; production has templates with this spelling
    const result = await s.caSignCSR(params(rsaCA, { hash: 'SHA256' }));
    assert.equal(result.signedBy, 'openssl');
    assert.match(await openssl(['x509', '-noout', '-text'], result.data), /sha256WithRSAEncryption/);
    assert.deepEqual(
      s.fallbacks.map((f) => f.reason),
      ['load CA key: hash SHA256'],
    );
  });

  test('reports PKCS#11 failures without the PIN', async () => {
    const pkcs11 = { uri: 'pkcs11:object=missing;type=private', modulePath: '/nonexistent.so', pin: 'secret-pin-1234' };
    // pkcs11js can't load the module, then openssl can't either
    const s = signer();
    await assert.rejects(s.caSignCSR({ ...params(rsaCA), pkcs11 }), (err: unknown) => {
      assert.ok(err instanceof SignerError && err.step === 'openssl dgst', String(err));
      assert.ok(!err.message.includes(pkcs11.pin));
      return true;
    });
    assert.deepEqual(s.fallbacks, []);
    // node-openssl-cert2 when forced
    const forced = signer({ forceOpenSSL: true });
    await assert.rejects(forced.caSignCSR({ ...params(rsaCA), pkcs11 }), (err: unknown) => {
      assert.ok(err instanceof SignerError && err.step === 'sign with OpenSSL', String(err));
      assert.ok(!err.message.includes(pkcs11.pin));
      return true;
    });
  });

  test('does not fall back when the request itself is refused', async () => {
    const s = signer();
    await assert.rejects(
      s.caSignCSR({ ...params(rsaCA), password: 'wrong-passphrase' }),
      (err: unknown) => err instanceof SignerError && err.step === 'load CA key',
    );
    assert.deepEqual(s.fallbacks, []);
  });

  describe('x509.CASignCSR', () => {
    test('passes a native certificate like node-openssl-cert2 does', async () => {
      const { err, result } = await callback(signer(), params(rsaCA));
      assert.equal(err, false);
      assert.ok(result && result.data && issuedBy(result.data, rsaCA));
      assert.equal(result.serial, new X509Certificate(result.data).serialNumber);
      assert.equal(result.command, null);
      assert.equal(result.signedBy, 'native');
    });

    test("passes node-openssl-cert2's own result when it falls back", async () => {
      const s = signer({ forceOpenSSL: true });
      const { err, result } = await callback(s, params(rsaCA));
      assert.equal(err, false);
      assert.ok(result && result.data && issuedBy(result.data, rsaCA));
      assert.match(result.command?.[0] ?? '', /^openssl ca /);
      assert.equal(result.signedBy, 'openssl');
      assert.equal(s.fallbacks.length, 1);
    });

    test('passes a refusal as an error', async () => {
      const { err, result } = await callback(signer(), { ...params(rsaCA), password: 'wrong-passphrase' });
      assert.ok(err instanceof SignerError && err.step === 'load CA key', String(err));
      assert.deepEqual(result, { command: null, data: null });
    });
  });
});
