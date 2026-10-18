// The differential harness (ADR 0001): the native signer against node-openssl-cert2's CASignCSR.
// Every case must come out identical apart from the serial number and signature value, except the
// intended differences of ADR 0002.
import assert from 'node:assert/strict';
import { X509Certificate } from 'node:crypto';
import { availableParallelism } from 'node:os';
import { describe, test } from 'node:test';
import { CertificationRequest } from '@peculiar/asn1-csr';
import { AsnConvert } from '@peculiar/asn1-schema';
import { shadowCASignCSR } from '../../src/index.ts';
import { opensslVerify } from './compare.ts';
import { corpus } from './corpus.ts';
import { differential } from './harness.ts';
import { nativeSigner } from './native.ts';
import { referenceSigner, type Signer } from './reference.ts';

// production containers run in UTC, and node-openssl-cert2 formats -startdate/-enddate in local time
process.env.TZ = 'UTC';

// cases where the reference path itself refuses to sign; a candidate must refuse them too
const referenceRejects = new Set<string>([
  // past the year 9999, or past what a JavaScript date holds
  'template with days 9999999',
  'template with days 999999999',
  'template with unknown EKU name',
  // node-openssl-cert2 0.7.37 refuses hashes with other characters and control characters anywhere
  'template with hash with a trailing space',
  'template with custom AIA URLs with a tab and spaces',
]);

// cases the native signer leaves to OpenSSL (UnsupportedError): createSigner falls back and issues the
// reference's certificate, and shadow mode reports them as unsupported
const fallsBack = new Set<string>(['template with hash SHA256']);

// ADR 0005: CSRs with a version other than v1, which the reference refuses and the candidate signs
const csrVersions = new Set<string>(['CSR version 2 (Meraki MDM)', 'CSR version 2 (SCEP CA request)']);

// ADR 0002: where the reference empties the subject, the candidate issues the full subject. Each case
// lists that subject as node:crypto prints it (RFC 2253 escapes). Since node-openssl-cert2 0.7.38 the
// reference escapes `/`, `+` and `\` in -subj and csr.parse reads subjects correctly, so only nested
// arrays are left.
const fullSubjects = new Map<string, string>([
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
      const params = await c.build();
      const outcome = await differential(params, candidate);
      if (referenceRejects.has(c.name)) {
        assert.equal(outcome.kind, 'both rejected', JSON.stringify(outcome));
        return;
      }
      if (fallsBack.has(c.name)) {
        assert.ok(outcome.kind === 'one rejected' && outcome.reference === 'signed', JSON.stringify(outcome));
        const referencePEM = await referenceSigner(params);
        const shadow = await shadowCASignCSR(params, referencePEM);
        assert.equal(shadow.outcome, 'unsupported', JSON.stringify(shadow));
        assert.equal(shadow.signature, 'valid', 'shadow signature');
        return;
      }
      if (csrVersions.has(c.name)) {
        // node-openssl-cert2 reports "Could not find certificate from <stdin>", not openssl's reason
        assert.ok(outcome.kind === 'one rejected' && outcome.candidatePEM, JSON.stringify(outcome));
        const cert = new X509Certificate(outcome.candidatePEM);
        // the certificate carries the CSR's key, and OpenSSL verifies it
        const csr = AsnConvert.parse(
          Buffer.from(params.csr.replace(/-----[^-]+-----|\s/g, ''), 'base64'),
          CertificationRequest,
        );
        assert.deepEqual(
          cert.publicKey.export({ type: 'spki', format: 'der' }),
          Buffer.from(AsnConvert.serialize(csr.certificationRequestInfo.subjectPKInfo)),
        );
        assert.equal(await opensslVerify(outcome.candidatePEM, params.ca), undefined, 'openssl verify');
        const shadow = await shadowCASignCSR(params, outcome.candidatePEM);
        assert.equal(shadow.outcome, 'match', JSON.stringify(shadow));
        assert.equal(shadow.signature, 'valid', 'shadow signature');
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
      // shadow mode rebuilds the reference's TBS exactly, apart from the same intended differences
      const shadow = await shadowCASignCSR(params, outcome.referencePEM);
      // and every reference certificate's signature verifies with its CA, every key type included
      assert.equal(shadow.signature, 'valid', 'shadow signature');
      if (fullSubject !== undefined) {
        assert.ok(shadow.outcome === 'differ', JSON.stringify(shadow));
        assert.deepEqual(shadow.fields, ['subject'], 'shadow');
      } else {
        assert.equal(shadow.outcome, 'match', JSON.stringify(shadow));
        // the native TBS is the reference certificate's TBS, byte for byte
        assert.ok(
          Buffer.from(new X509Certificate(outcome.referencePEM).raw).includes(Buffer.from(shadow.tbs)),
          'TBS bytes',
        );
      }
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
