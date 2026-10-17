// The allowlist must name exactly what the differential harness covers: every CA key type with
// every hash the corpus signs with, per backend.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { backendSpecs } from '../test/differential/backends.ts';
import { caHashes } from '../test/differential/corpus.ts';
import { caKeySpecs, generateKey, type KeySpec } from '../test/differential/fixtures.ts';
import { allowlisted, softwareKey } from './index.ts';

async function algorithms(specs: KeySpec[]) {
  const covered = await Promise.all(
    specs.map(async (spec) => {
      const { privateKey } = await generateKey(spec);
      return caHashes(spec).map((hash) => softwareKey(privateKey, undefined, hash).algorithm);
    }),
  );
  return [...new Set(covered.flat())].sort();
}

test('allowlists exactly the software algorithms the differential harness covers', async () => {
  assert.deepEqual([...allowlisted('software')].sort(), await algorithms(caKeySpecs));
});

for (const [backend, specs] of Object.entries(backendSpecs)) {
  test(`allowlists exactly the ${backend} algorithms the backend harness covers`, async () => {
    assert.deepEqual([...allowlisted(backend)].sort(), await algorithms(specs));
  });
}

test('allowlists for KMS only what passed against the real service', () => {
  assert.deepEqual([...allowlisted('kms')], ['sha256WithRSAEncryption']);
  assert.equal(allowlisted('unknown').size, 0);
});
