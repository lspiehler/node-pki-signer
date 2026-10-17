// The kms backend against Google Cloud KMS itself (ADR 0003), which the stand-in client in
// test/differential/fake-kms.ts can't prove. Skipped unless LIVE_KMS_KEY_VERSION names a key version
// (`projects/…/cryptoKeyVersions/N`) that Application Default Credentials may sign with. The
// reference is node-openssl-cert2 through libkmsp11 (LIVE_KMS_PKCS11_MODULE, /usr/lib/kms/libkmsp11.so
// by default), as the IoT HSM agent signs today.
//
// The key may be a production CA's. The certificates are issued by a throwaway issuer certificate
// that carries the KMS public key under a test name, are valid for an hour and never leave the test.
// KMS bills every signature, so the test makes a handful and refuses to make more than `maxSigns`.
import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, before, describe, test } from 'node:test';
import { allowlisted, caSignCSR, type KmsClient, type NativeSettings, type SignParams } from '../../src/index.ts';
import { caKeySpecs, generateKey } from '../differential/fixtures.ts';
import { differential } from '../differential/harness.ts';
import { testIssuer, testRequest, verifyPartialChain } from './issuer.ts';

process.env.TZ = 'UTC';

const keyVersion = process.env.LIVE_KMS_KEY_VERSION ?? '';
const modulePath = process.env.LIVE_KMS_PKCS11_MODULE ?? '/usr/lib/kms/libkmsp11.so';
const maxSigns = 12;

/** The KMS client, counting asymmetricSign calls and refusing more than `maxSigns`. */
type Client = KmsClient & { getPublicKey(r: { name: string }): Promise<[{ pem?: string | null }]> };
class CappedKms implements KmsClient {
  signs = 0;
  readonly client: Client;
  constructor(client: Client) {
    this.client = client;
  }
  asymmetricSign(request: Parameters<KmsClient['asymmetricSign']>[0]) {
    if (++this.signs > maxSigns) throw new Error(`more than ${maxSigns} KMS signatures`);
    return this.client.asymmetricSign(request);
  }
}

describe('live: kms backend against Google Cloud KMS', { skip: !keyVersion && 'needs LIVE_KMS_KEY_VERSION' }, () => {
  let kms: CappedKms;
  let issuer: string;
  let configDir: string;
  // projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/n
  const [, keyRing = '', cryptoKey = ''] = /^(.+\/keyRings\/[^/]+)\/cryptoKeys\/([^/]+)\//.exec(keyVersion) ?? [];

  before(async () => {
    const { KeyManagementServiceClient } = await import('@google-cloud/kms');
    kms = new CappedKms(new KeyManagementServiceClient() as unknown as Client);
    const [{ pem }] = await kms.client.getPublicKey({ name: keyVersion });
    assert.ok(pem, 'KMS getPublicKey returned no key');
    issuer = await testIssuer(pem, 'node-pki-signer KMS live test (untrusted)');
    // libkmsp11 reads its key ring from a file only its owner can write
    configDir = await mkdtemp(join(tmpdir(), 'pki-signer-kms-'));
    await writeFile(join(configDir, 'kms.yml'), `tokens:\n  - key_ring: ${keyRing}\n`, { mode: 0o600 });
    process.env.KMS_PKCS11_CONFIG = join(configDir, 'kms.yml');
  });
  after(async () => {
    if (configDir) await rm(configDir, { recursive: true, force: true });
  });

  // the agent's parameters for a KMS key, plus kms.keyVersion
  async function params(hash: string, ca = issuer): Promise<SignParams> {
    const request = await testRequest(ca, hash);
    return {
      ...request,
      options: { ...request.options, module: modulePath },
      pkcs11: { uri: `pkcs11:object=${cryptoKey};type=private`, pin: '', modulePath },
      kms: { keyVersion },
    };
  }

  const settings = (extra: Partial<NativeSettings> = {}): NativeSettings => ({
    backends: ['kms'],
    kms: () => Promise.resolve(kms),
    ...extra,
  });

  test('signs like libkmsp11 with the allowlisted algorithm', async () => {
    const p = await params('sha256');
    const outcome = await differential(p, async (p) => (await caSignCSR(p, settings())).data, true);
    assert.equal(outcome.kind, 'both signed', JSON.stringify(outcome));
    assert.deepEqual(outcome.differences, [], 'TBS fields differ');
    assert.deepEqual(outcome.text, [], 'openssl x509 -text differs');
    assert.match(await verifyPartialChain(outcome.candidatePEM, issuer), /: OK\n$/);
    assert.ok(allowlisted('kms').has('sha256WithRSAEncryption'));
  });

  test('passes on KMS refusing a digest that is not the key’s', async () => {
    // past the allowlist, so the request reaches KMS
    const s = settings({ allowlisted: () => allowlisted('software') });
    await assert.rejects(caSignCSR(await params('sha512'), s), /^SignerError: KMS asymmetricSign: 3 INVALID_ARGUMENT/);
  });

  test("refuses a CA certificate whose key isn't the KMS key", async () => {
    const other = await generateKey(caKeySpecs.find((s) => s.name === 'RSA-2048')!);
    const wrong = await testIssuer(other.publicKey, 'node-pki-signer KMS live test (wrong key)');
    await assert.rejects(caSignCSR(await params('sha256', wrong), settings()), /^SignerError: verify signature: /);
  });

  test('signs within the latency budget', async (t) => {
    const times: number[] = [];
    for (let i = 0; i < 5; i++) {
      const p = await params('sha256');
      const start = performance.now();
      await caSignCSR(p, settings());
      times.push(performance.now() - start);
    }
    t.diagnostic(`KMS signatures: ${kms.signs}; caSignCSR ms: ${times.map((ms) => ms.toFixed(0)).join(', ')}`);
    // the first call opens the gRPC channel; libkmsp11 through openssl ca takes about 1.8 s each
    assert.ok(Math.min(...times) < 1000, `fastest signature took ${Math.min(...times).toFixed(0)} ms`);
  });
});
