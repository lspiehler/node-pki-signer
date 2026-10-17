// The differential harness per key backend (ADR 0003): every CA key type and hash a backend can sign,
// against node-openssl-cert2 signing with the same key. PKCS#11 keys live on a SoftHSM token, signed
// by `openssl ca` through pkcs11-provider as the IoT HSM agent does. KMS keys are signed by a stand-in
// client (fake-kms.ts), so this checks the requests and signatures, not Google's service.
import assert from 'node:assert/strict';
import { availableParallelism } from 'node:os';
import { after, before, describe, test } from 'node:test';
import {
  allowlisted,
  caSignCSR,
  Pkcs11Sessions,
  type NativeSettings,
  type Pkcs11KeyRef,
  type SignParams,
} from '../../src/index.ts';
import { backendSpecs } from './backends.ts';
import { caKeyCases } from './corpus.ts';
import { FakeKms, kmsSupports } from './fake-kms.ts';
import { differential } from './harness.ts';
import { createToken, findSoftHSM, type Token } from './softhsm.ts';

process.env.TZ = 'UTC';

const concurrency = availableParallelism();

function assertSame(outcome: Awaited<ReturnType<typeof differential>>) {
  assert.equal(outcome.kind, 'both signed', JSON.stringify(outcome));
  assert.deepEqual(outcome.differences, [], 'TBS fields differ');
  assert.deepEqual(outcome.text, [], 'openssl x509 -text differs');
  assert.deepEqual(outcome.verify, { reference: undefined, candidate: undefined }, 'openssl verify');
}

const native = (settings: NativeSettings) => async (params: SignParams) => (await caSignCSR(params, settings)).data;

describe('differential: openssl backend', { concurrency }, () => {
  for (const c of caKeyCases.filter((c) => backendSpecs.openssl!.includes(c.spec))) {
    test(c.name, async () => {
      assertSame(await differential(await c.build(), native({ backends: ['openssl'] })));
    });
  }
});

// SoftHSM and pkcs11-provider are in the CI image; elsewhere the PKCS#11 tests need them installed
const softhsm = await findSoftHSM();
const skip = 'missing' in softhsm && !process.env.CI ? `needs ${softhsm.missing}` : false;

describe('differential: PKCS#11 backends', { skip }, () => {
  let token: Token;
  const sessions = new Pkcs11Sessions();

  before(async () => {
    if ('missing' in softhsm) throw new Error(`needs ${softhsm.missing}`);
    token = await createToken(softhsm.modulePath);
  });
  after(async () => {
    sessions.close();
    await token.remove();
  });

  // the agent's parameters: the token key instead of the PEM, and the module for node-openssl-cert2
  async function onToken(params: SignParams): Promise<SignParams> {
    const ref = await token.importKey(params.key, params.password ?? '');
    return { ...params, key: '', password: '', options: { ...params.options, module: ref.modulePath }, pkcs11: ref };
  }

  for (const backend of ['pkcs11', 'openssl-pkcs11']) {
    describe(backend, { concurrency }, () => {
      for (const c of caKeyCases.filter((c) => backendSpecs[backend]!.includes(c.spec))) {
        test(c.name, async () => {
          const params = await onToken(await c.build());
          assertSame(await differential(params, native({ backends: [backend], pkcs11: sessions })));
        });
      }
    });
  }

  test('refuses a wrong PIN without falling back', async () => {
    const [c] = caKeyCases;
    const params = await onToken(await c!.build());
    const pkcs11 = { ...(params.pkcs11 as Pkcs11KeyRef), pin: 'wrong-pin-0000' };
    await assert.rejects(caSignCSR({ ...params, pkcs11 }, { backends: ['pkcs11'], pkcs11: sessions }), (err: Error) => {
      assert.match(err.message, /^PKCS#11 login: CKR_PIN_INCORRECT/);
      assert.ok(!err.message.includes(pkcs11.pin));
      return true;
    });
    // the right PIN logs in again
    await caSignCSR(params, { backends: ['pkcs11'], pkcs11: sessions });
  });

  test("refuses a token key that isn't the CA's", async () => {
    const [first, other] = [caKeyCases[0]!, caKeyCases.find((c) => c.spec.name === 'RSA-4096')!];
    const params = await onToken(await first.build());
    const wrong = await onToken(await other.build());
    for (const backend of ['pkcs11', 'openssl-pkcs11']) {
      await assert.rejects(
        caSignCSR({ ...params, pkcs11: wrong.pkcs11 }, { backends: [backend], pkcs11: sessions }),
        /^SignerError: verify signature: /,
      );
    }
  });
});

describe('differential: kms backend (stand-in client)', { concurrency }, () => {
  const kms = new FakeKms();
  // not allowlisted until tested against the real service, so let the harness past the allowlist
  const settings = { backends: ['kms'], kms: () => Promise.resolve(kms), allowlisted: () => allowlisted('software') };
  const supported = caKeyCases.filter((c) => {
    const curve = (c.spec.options as { namedCurve?: string } | undefined)?.namedCurve;
    return kmsSupports(c.spec.type, curve, c.spec.pqc ? null : c.hash);
  });
  for (const c of supported) {
    test(c.name, async () => {
      const params = await c.build();
      const keyVersion = kms.add(params.key, params.password ?? '');
      assertSame(await differential({ ...params, kms: { keyVersion } }, native(settings)));
    });
  }

  test('passes KMS refusals on', async () => {
    const c = caKeyCases.find((c) => c.spec.name === 'EC-P256' && c.hash === 'sha384')!;
    const params = await c.build();
    const keyVersion = kms.add(params.key, params.password ?? '');
    await assert.rejects(
      caSignCSR({ ...params, kms: { keyVersion } }, settings),
      /^SignerError: KMS asymmetricSign: 3 INVALID_ARGUMENT/,
    );
  });
});
