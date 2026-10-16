// The differential harness (ADR 0001). Until the native path exists, the candidate is the reference
// itself: every case must come out identical apart from the serial number and signature value,
// which proves the corpus and the comparison are deterministic. Phase 1 swaps in the new signer.
import assert from 'node:assert/strict';
import { availableParallelism } from 'node:os';
import { describe, test } from 'node:test';
import { corpus } from './corpus.ts';
import { differential } from './harness.ts';
import { referenceSigner, type Signer } from './reference.ts';

// production containers run in UTC, and node-openssl-cert2 formats -startdate/-enddate in local time
process.env.TZ = 'UTC';

// cases where the reference path itself refuses to sign; a candidate must refuse them too
const referenceRejects = new Set<string>(['CSR punctuation in subject', 'CSR equals sign in subject']);

const candidate: Signer = referenceSigner;

describe('differential: reference against candidate', { concurrency: availableParallelism() }, () => {
  for (const c of corpus) {
    test(c.name, async () => {
      const outcome = await differential(await c.build(), candidate);
      if (referenceRejects.has(c.name)) {
        assert.equal(outcome.kind, 'both rejected', JSON.stringify(outcome));
        return;
      }
      assert.equal(outcome.kind, 'both signed', JSON.stringify(outcome));
      assert.deepEqual(outcome.differences, [], 'TBS fields differ');
      assert.deepEqual(outcome.text, [], 'openssl x509 -text differs');
      assert.deepEqual(outcome.verify, { reference: undefined, candidate: undefined }, 'openssl verify');
    });
  }
});

describe('differential harness', () => {
  const [first] = corpus;

  test('reports a changed extension', async () => {
    // drops the CRL distribution point, as a broken candidate might
    const broken: Signer = (params) => {
      const extensions = { ...params.options.extensions };
      delete extensions.crlDistributionPoints;
      return referenceSigner({ ...params, options: { ...params.options, extensions } });
    };
    const outcome = await differential(await first!.build(), broken);
    assert.equal(outcome.kind, 'both signed');
    const fields = outcome.differences.map((d) => d.field);
    assert.ok(fields.includes('extension 2.5.29.31'), fields.join(', '));
    assert.ok(fields.includes('extension order'), fields.join(', '));
    assert.ok(
      outcome.text.some((l) => l.includes('CRL Distribution Points')),
      outcome.text.join('\n'),
    );
  });

  test('reports a changed validity', async () => {
    const broken: Signer = (params) =>
      referenceSigner({ ...params, options: { ...params.options, enddate: new Date(Date.UTC(2030, 0, 1)) } });
    const outcome = await differential(await first!.build(), broken);
    assert.equal(outcome.kind, 'both signed');
    assert.deepEqual(
      outcome.differences.map((d) => d.field),
      ['validity'],
    );
  });

  test('reports a refusal', async () => {
    const refusing: Signer = () => Promise.reject(new Error('refused'));
    const outcome = await differential(await first!.build(), refusing);
    assert.deepEqual(outcome, { kind: 'one rejected', reference: 'signed', candidate: 'refused' });
  });
});
