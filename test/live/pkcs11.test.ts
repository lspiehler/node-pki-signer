// The PKCS#11 backends against a real token (ADR 0003), e.g. a YubiKey, which SoftHSM in
// test/differential/backends.test.ts can't stand in for. Skipped unless LIVE_PKCS11_URI names a
// private key (`pkcs11:serial=…;id=%0a;type=private`) on the token of LIVE_PKCS11_MODULE, with its
// user PIN in LIVE_PKCS11_PIN. The reference is node-openssl-cert2 (`openssl ca` with pkcs11-provider),
// as the IoT HSM agent signs today.
//
// The key may be a production CA's: see issuer.ts. Never put a wrong PIN here; a YubiKey blocks after
// three.
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { after, before, describe, test } from 'node:test';
import { promisify } from 'node:util';
import { caSignCSR, Pkcs11Sessions, type NativeSettings, type SignParams } from '../../src/index.ts';
import { differential } from '../differential/harness.ts';
import { testIssuer, testRequest, verifyPartialChain } from './issuer.ts';

process.env.TZ = 'UTC';

const run = promisify(execFile);
const uri = process.env.LIVE_PKCS11_URI ?? '';
const modulePath = process.env.LIVE_PKCS11_MODULE ?? '/usr/lib/x86_64-linux-gnu/libykcs11.so';
const pin = process.env.LIVE_PKCS11_PIN ?? '';

describe('live: PKCS#11 backends against a token', { skip: !uri && 'needs LIVE_PKCS11_URI' }, () => {
  const sessions = new Pkcs11Sessions();
  let issuer: string;

  before(async () => {
    assert.ok(pin, 'needs LIVE_PKCS11_PIN');
    const { stdout } = await run(
      'openssl',
      [
        'pkey',
        '-pubin',
        '-in',
        uri.replace('type=private', 'type=public'),
        '-provider',
        'pkcs11',
        '-provider',
        'default',
      ],
      { env: { ...process.env, PKCS11_PROVIDER_MODULE: modulePath } },
    );
    issuer = await testIssuer(stdout, 'node-pki-signer PKCS#11 live test (untrusted)');
  });
  after(() => {
    sessions.close();
  });

  // the agent's parameters for a token key
  async function params(hash: string): Promise<SignParams> {
    const request = await testRequest(issuer, hash);
    return { ...request, options: { ...request.options, module: modulePath }, pkcs11: { uri, pin, modulePath } };
  }

  const settings = (backend: string): NativeSettings => ({ backends: [backend], pkcs11: sessions });

  // one at a time and the reference first, as on SoftHSM; pkcs11js stays logged in meanwhile
  for (const backend of ['pkcs11', 'openssl-pkcs11']) {
    for (const hash of ['sha1', 'sha224', 'sha256', 'sha384', 'sha512']) {
      test(`${backend} ${hash} signs like openssl ca`, async () => {
        const p = await params(hash);
        const outcome = await differential(p, async (p) => (await caSignCSR(p, settings(backend))).data, true);
        assert.equal(outcome.kind, 'both signed', JSON.stringify(outcome));
        assert.deepEqual(outcome.differences, [], 'TBS fields differ');
        assert.deepEqual(outcome.text, [], 'openssl x509 -text differs');
        assert.match(await verifyPartialChain(outcome.candidatePEM, issuer), /: OK\n$/);
      });
    }
  }

  test('pkcs11 signs with one login', async (t) => {
    const times: number[] = [];
    for (let i = 0; i < 5; i++) {
      const p = await params('sha256');
      const start = performance.now();
      await caSignCSR(p, settings('pkcs11'));
      times.push(performance.now() - start);
    }
    t.diagnostic(`caSignCSR ms: ${times.map((ms) => ms.toFixed(0)).join(', ')}`);
  });
});
