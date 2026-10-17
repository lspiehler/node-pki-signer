// The allowlist must name exactly what the differential harness covers: every CA key type with
// every hash the corpus signs with.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { caHashes } from '../test/differential/corpus.ts';
import { caKeySpecs, generateKey } from '../test/differential/fixtures.ts';
import { checkAllowlist } from './allowlist.ts';
import { allowlisted, softwareKey, UnsupportedError, type SigningKey } from './index.ts';

test('allowlists exactly the software algorithms the differential harness covers', async () => {
  const covered = await Promise.all(
    caKeySpecs.map(async (spec) => {
      const { privateKey } = await generateKey(spec);
      return caHashes(spec).map((hash) => softwareKey(privateKey, undefined, hash).algorithm);
    }),
  );
  assert.deepEqual([...allowlisted('software')].sort(), [...new Set(covered.flat())].sort());
});

test('leaves algorithms to OpenSSL that are not allowlisted for the backend, or forced', () => {
  const key = (backend: string, algorithm: string): SigningKey => ({
    backend,
    algorithm,
    publicKey: () => Promise.resolve(new Uint8Array()),
    sign: () => Promise.resolve(new Uint8Array()),
  });
  const unsupported = (err: unknown) => err instanceof UnsupportedError && err.step === 'check allowlist';
  assert.doesNotThrow(() => {
    checkAllowlist(key('software', 'ML-DSA-65'));
  });
  assert.throws(() => {
    checkAllowlist(key('software', 'Ed25519'));
  }, unsupported);
  assert.throws(() => {
    checkAllowlist(key('pkcs11', 'sha256WithRSAEncryption'));
  }, unsupported);
  assert.throws(() => {
    checkAllowlist(key('software', 'ML-DSA-65'), ['ML-DSA-65']);
  }, unsupported);
});
