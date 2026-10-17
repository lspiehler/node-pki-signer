// The differential harness (ADR 0001): the native signer against node-openssl-cert2's CASignCSR.
// Every case must come out identical apart from the serial number and signature value, except the
// intended differences of ADR 0002.
import assert from 'node:assert/strict';
import { X509Certificate } from 'node:crypto';
import { availableParallelism } from 'node:os';
import { describe, test } from 'node:test';
import { corpus } from './corpus.ts';
import { differential } from './harness.ts';
import { nativeSigner } from './native.ts';
import { referenceSigner, type Signer } from './reference.ts';

// production containers run in UTC, and node-openssl-cert2 formats -startdate/-enddate in local time
process.env.TZ = 'UTC';

// cases where the reference path itself refuses to sign; a candidate must refuse them too
const referenceRejects = new Set<string>(['CSR equals sign in subject']);

// ADR 0002: where the reference truncates, empties or refuses the subject, the candidate issues the
// full subject. Each case lists that subject as node:crypto prints it (RFC 2253 escapes).
const fullSubjects = new Map<string, string>([
  // `/`, `+` and `\` cut the reference's -subj short; the CSR cases carry csr.parse's own mangling
  ['admin override subject with slash', 'C=US\nO=Ops/Infra\nCN=override.example.com'],
  ['admin override subject with plus', 'C=US\nO=a\\+b\nCN=override.example.com'],
  ['admin override subject with backslash', 'C=US\nO=back\\\\slash\nCN=override.example.com'],
  ['CSR slash and backslash in subject', 'C=US\nO=Ops\\, Infra\nCN=back\\\\slash'],
  // the reference refuses this one: -subj reads the escaped + as a second attribute of the RDN
  ['CSR punctuation in subject', 'C=US\nO=Smith\\, Jones & Co.\nOU=R&D (Ops)\nCN=a\\+b quoted #1 \\<x\\>\\; y'],
  // templates saved with nested arrays ([["US"]]): the reference issues the attributes before the
  // first nested one, here none
  ['template dev template 3', 'C=US\nST=Louisiana\nL=New Orleans\nO=Example Org\nCN=www.example.com'],
  ['template dev template 4', 'C=US\nO=Example Org\nCN=www.example.com'],
  ['template dev template 5', 'C=US\nST=Louisiana\nL=New Orleans\nO=Example Org\nCN=www.example.com'],
  ['template dev template 8', 'C=US\nST=Louisiana\nL=New Orleans\nO=Example Org\nCN=www.example.com'],
  ['template dev template 9', 'C=US\nL=New Orleans\nO=Example Org\nCN=www.example.com\nserialNumber=1234567890123456'],
  ['template dev template 12', 'C=US\nST=Louisiana\nO=Example Org\nCN=www.example.com'],
  ['template dev template 21', 'C=US\nST=Louisiana\nO=Example Org\nCN=www.example.com'],
  ['template dev template 68', 'C=US\nO=Example Org\nCN=www.example.com'],
  ['template dev template 72', 'C=US\nO=Example Org\nCN=www.example.com'],
  ['template dev template 81', 'C=BR\nST=Louisiana\nL=New Orleans\nO=Example Org\nOU=Example Unit\nCN=www.example.com'],
]);

const candidate: Signer = nativeSigner;

describe('differential: reference against candidate', { concurrency: availableParallelism() }, () => {
  for (const c of corpus) {
    test(c.name, async () => {
      const outcome = await differential(await c.build(), candidate);
      if (referenceRejects.has(c.name)) {
        assert.equal(outcome.kind, 'both rejected', JSON.stringify(outcome));
        return;
      }
      const fullSubject = fullSubjects.get(c.name);
      if (fullSubject !== undefined) {
        assert.ok(outcome.kind !== 'both rejected' && outcome.candidatePEM, JSON.stringify(outcome));
        assert.equal(new X509Certificate(outcome.candidatePEM).subject, fullSubject, 'full subject');
        if (outcome.kind !== 'both signed') return;
      }
      assert.equal(outcome.kind, 'both signed', JSON.stringify(outcome));
      assert.deepEqual(
        outcome.differences.filter((d) => !(fullSubject !== undefined && d.field === 'subject')),
        [],
        'TBS fields differ',
      );
      assert.deepEqual(
        outcome.text.filter((l) => !(fullSubject !== undefined && /^[-+]\s+Subject:/.test(l))),
        [],
        'openssl x509 -text differs',
      );
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
