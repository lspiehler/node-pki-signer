// signFinalCertificate: the final certificate is the precertificate's TBS with the poison swapped for the SCT list,
// byte for byte, for every CA key type and backend, and anything else is refused.
import { AsnConvert, OctetString } from '@peculiar/asn1-schema';
import { Certificate, Extension, Version } from '@peculiar/asn1-x509';
import assert from 'node:assert/strict';
import { createPrivateKey, sign, X509Certificate } from 'node:crypto';
import { join } from 'node:path';
import { after, before, describe, test } from 'node:test';
import {
  caKeySpecs,
  createCA,
  createCSR,
  withFiles,
  type IssuingCA,
  type KeySpec,
} from '../test/differential/fixtures.ts';
import { FakeKms } from '../test/differential/fake-kms.ts';
import { openssl } from '../test/differential/openssl.ts';
import { createToken, findSoftHSM, type Token } from '../test/differential/softhsm.ts';
import { caSignCSR } from './ca-sign-csr.ts';
import { encodeTlv, readChildren, readTlv } from './der.ts';
import { signFinalCertificate, type FinalCertificateParams } from './final-certificate.ts';
import { createSigner, Pkcs11Sessions, SignerError, UnsupportedError } from './index.ts';
import type { KeySettings } from './keys.ts';

const POISON = '1.3.6.1.4.1.11129.2.4.3';
const SCT_LIST = '1.3.6.1.4.1.11129.2.4.2';
const poisonOption = { OID: POISON, value: 'critical,ASN1:NULL' };

// SoftHSM and pkcs11-provider are in the CI image; elsewhere the PKCS#11 tests need them installed
const softhsm = await findSoftHSM();
const skip = 'missing' in softhsm && !process.env.CI ? `needs ${softhsm.missing}` : false;

const spec = (name: string): KeySpec => {
  const found = caKeySpecs.find((s) => s.name === name);
  if (!found) throw new Error(name);
  return found;
};

/** A DER OCTET STRING around a TLS SCT list of SCTs whose signatures are `sizes` bytes, as sct-list.ts builds it. */
function sctList(sizes: number[]): Uint8Array {
  const vector = (bytes: Buffer) => Buffer.concat([Buffer.from([bytes.length >> 8, bytes.length & 0xff]), bytes]);
  const scts = sizes.map((size, i) =>
    vector(
      Buffer.concat([
        Buffer.from([0]),
        Buffer.alloc(32, i + 1),
        Buffer.from('0000019a00000000', 'hex'),
        Buffer.from([0, 0]),
        Buffer.from([4, 3]),
        vector(Buffer.alloc(size, 0x5a)),
      ]),
    ),
  );
  const list = vector(Buffer.concat(scts));
  return new Uint8Array(AsnConvert.serialize(new OctetString(list)));
}

/** The extensions' OIDs in order. */
const extensionOIDs = (pem: string) =>
  (AsnConvert.parse(new X509Certificate(pem).raw, Certificate).tbsCertificate.extensions ?? []).map((e) => e.extnID);

/** The precertificate re-signed by the CA's key after `change` (to shape what the library must refuse). */
function resign(pem: string, ca: IssuingCA, change: (cert: Certificate) => void): string {
  const cert = AsnConvert.parse(new X509Certificate(pem).raw, Certificate);
  change(cert);
  const tbs = new Uint8Array(AsnConvert.serialize(cert.tbsCertificate));
  const key = createPrivateKey({ key: ca.key, passphrase: ca.password });
  const signature = sign('sha256', tbs, key);
  const der = AsnConvert.serialize(
    new Certificate({
      tbsCertificate: cert.tbsCertificate,
      signatureAlgorithm: cert.signatureAlgorithm,
      signatureValue: new Uint8Array(signature).buffer,
    }),
  );
  return new X509Certificate(Buffer.from(der)).toString();
}

/** A precertificate `openssl x509 -req` signs with exactly these extension lines, in this order. */
function opensslPrecert(ca: IssuingCA, csr: string, extensions: string[], args: string[] = []): Promise<string> {
  return withFiles(
    {
      'ca.pem': ca.cert,
      'ca.key': ca.key,
      'req.pem': csr,
      'ext.cnf': ['subjectKeyIdentifier = none', 'authorityKeyIdentifier = none', ...extensions].join('\n'),
    },
    (dir) =>
      openssl(
        [
          'x509',
          '-req',
          '-in',
          join(dir, 'req.pem'),
          '-CA',
          join(dir, 'ca.pem'),
          '-CAkey',
          join(dir, 'ca.key'),
          '-passin',
          'stdin',
          '-days',
          '7',
          '-set_serial',
          '0x0123456789abcdef',
          '-extfile',
          join(dir, 'ext.cnf'),
          ...args,
        ],
        ca.password,
      ),
  );
}

/** Checks a final certificate as a relying party would: OpenSSL verifies it, and it matches its precertificate. */
async function assertFinal(final: string, precert: string, ca: IssuingCA, list: Uint8Array, decodes = true) {
  const [p, f] = [new X509Certificate(precert), new X509Certificate(final)];
  assert.equal(f.serialNumber, p.serialNumber);
  assert.equal(f.validFrom, p.validFrom);
  assert.equal(f.validTo, p.validTo);
  assert.equal(f.subject, p.subject);
  assert.equal(
    f.publicKey.export({ type: 'spki', format: 'der' }).toString('hex'),
    p.publicKey.export({ type: 'spki', format: 'der' }).toString('hex'),
  );
  // the SCT list where the poison was, holding exactly the given bytes
  const before = extensionOIDs(precert);
  assert.deepEqual(
    extensionOIDs(final),
    before.map((oid) => (oid === POISON ? SCT_LIST : oid)),
  );
  const ext = AsnConvert.parse(f.raw, Certificate).tbsCertificate.extensions?.find((e) => e.extnID === SCT_LIST);
  assert.ok(ext);
  assert.equal(ext.critical, false);
  assert.deepEqual(new Uint8Array(ext.extnValue.buffer), list);
  await withFiles({ 'ca.pem': ca.cert, 'final.pem': final }, async (dir) => {
    assert.match(await openssl(['verify', '-CAfile', join(dir, 'ca.pem'), join(dir, 'final.pem')]), /: OK/);
    const text = await openssl(['x509', '-in', join(dir, 'final.pem'), '-noout', '-text']);
    assert.match(text, /CT Precertificate SCTs:/);
    // OpenSSL prints an SCT list too long for one SCT as bytes
    if (decodes) assert.match(text, /Signed Certificate Timestamp:/);
    assert.doesNotMatch(text, /CT Precertificate Poison/);
  });
}

describe('signFinalCertificate', () => {
  const cas = new Map<string, IssuingCA>();
  let csr: string;
  const list = sctList([71, 72]);
  const ca = (name: string) => {
    const found = cas.get(name);
    if (!found) throw new Error(name);
    return found;
  };
  /** A precertificate the library signs, as pkiaas asks for one (lib/template/processTemplate.js). */
  const precertificate = async (issuer: IssuingCA, hash?: string, extensions: Record<string, unknown> = {}) =>
    (
      await caSignCSR({
        csr,
        ca: issuer.cert,
        key: issuer.key,
        password: issuer.password,
        options: {
          ...(hash ? { hash } : {}),
          subject: { commonName: 'ct.example.com' },
          days: 7,
          extensions: {
            keyUsage: { critical: true, usages: ['digitalSignature'] },
            ...extensions,
            customOIDs: [poisonOption],
          },
        },
      })
    ).data;
  const params = (issuer: IssuingCA, precert: string, sct = list): FinalCertificateParams => ({
    precertificate: precert,
    sctList: sct,
    ca: issuer.cert,
    key: issuer.key,
    password: issuer.password,
  });

  before(async () => {
    const names = [
      'RSA-2048',
      'EC-P256',
      'EC-P384',
      'ML-DSA-44',
      'ML-DSA-65',
      'SLH-DSA-SHA2-128F',
      'SLH-DSA-SHAKE-128F',
    ];
    const built = await Promise.all(names.map((name) => createCA(spec(name))));
    built.forEach((issuer, i) => cas.set(names[i] ?? '', issuer));
    // a second CA with the same name and another key
    cas.set('RSA-2048 other key', await createCA(spec('RSA-2048')));
    csr = await createCSR(spec('EC-P256'), '/CN=ct.example.com');
  });

  for (const [name, hash] of [
    ['RSA-2048', undefined],
    ['RSA-2048', 'sha1'],
    ['RSA-2048', 'sha384'],
    ['RSA-2048', 'sha512'],
    ['EC-P256', undefined],
    ['EC-P256', 'sha512'],
    ['EC-P384', 'sha384'],
    ['ML-DSA-44', undefined],
    ['ML-DSA-65', undefined],
    ['SLH-DSA-SHA2-128F', undefined],
    ['SLH-DSA-SHAKE-128F', undefined],
  ] as const) {
    test(`${name}${hash ? ` ${hash}` : ''}: signs the final certificate from the precertificate`, async () => {
      const issuer = ca(name);
      const precert = await precertificate(issuer, hash);
      const result = await signFinalCertificate(params(issuer, precert));
      assert.equal(result.backend, 'software');
      assert.equal(result.serial, new X509Certificate(precert).serialNumber);
      await assertFinal(result.data, precert, issuer, list);
      // the same signature algorithm, inside and outside the TBS
      const [p, f] = [precert, result.data].map((pem) => AsnConvert.parse(new X509Certificate(pem).raw, Certificate));
      assert.equal(f?.signatureAlgorithm.algorithm, p?.signatureAlgorithm.algorithm);
    });
  }

  test("signs a precertificate OpenSSL signed (node-openssl-cert2's path)", async () => {
    const issuer = ca('RSA-2048');
    const signer = createSigner({ forceOpenSSL: true, onFallback: () => undefined });
    const { data, signedBy } = await signer.caSignCSR({
      csr,
      ca: issuer.cert,
      key: issuer.key,
      password: issuer.password,
      options: { subject: { commonName: 'ct.example.com' }, days: 7, extensions: { customOIDs: [poisonOption] } },
    });
    assert.equal(signedBy, 'openssl');
    await assertFinal((await signFinalCertificate(params(issuer, data))).data, data, issuer, list);
  });

  for (const [where, extensions] of [
    [
      'first',
      [`${POISON} = critical,ASN1:NULL`, 'basicConstraints = critical,CA:FALSE', 'keyUsage = digitalSignature'],
    ],
    [
      'in the middle',
      ['basicConstraints = critical,CA:FALSE', `${POISON} = critical,ASN1:NULL`, 'keyUsage = digitalSignature'],
    ],
    ['last', ['basicConstraints = critical,CA:FALSE', 'keyUsage = digitalSignature', `${POISON} = critical,ASN1:NULL`]],
    ['alone', [`${POISON} = critical,ASN1:NULL`]],
  ] as const) {
    test(`keeps the poison's place: ${where}`, async () => {
      const issuer = ca('RSA-2048');
      const precert = await opensslPrecert(issuer, csr, [...extensions]);
      await assertFinal((await signFinalCertificate(params(issuer, precert))).data, precert, issuer, list);
    });
  }

  test('writes every length in its shortest form across the 128, 256 and 65536 boundaries', async () => {
    const issuer = ca('EC-P256');
    const precert = await precertificate(issuer);
    const sizes = new Set<number>();
    // the SCT extension, the Extensions SEQUENCE, [3] and the TBS each cross 128 and 256 somewhere in here
    for (let size = 0; size <= 300; size++) sizes.add(size);
    // the list's OCTET STRING content around 65535 and 65536 bytes: the list and SCT lengths (2 + 2), 47 bytes of
    // SCT before the signature, and the signature; 65537 is the most a TLS list can be
    for (const total of [65534, 65535, 65536, 65537]) sizes.add(total - 51);
    for (const size of sizes) {
      const sct = sctList([size]);
      const result = await signFinalCertificate(params(issuer, precert, sct));
      const der = new Uint8Array(new X509Certificate(result.data).raw);
      // every header in the certificate is minimal: walking it never meets a longer form than needed
      const walk = (offset: number, limit: number) => {
        for (let at = offset; at < limit;) {
          const tlv = readTlv(der, at, limit, 'test');
          const length = tlv.end - tlv.contentStart;
          const header = tlv.contentStart - tlv.start - 1;
          assert.equal(header, length < 0x80 ? 1 : 1 + Math.ceil(Math.log2(length + 1) / 8), `size ${size}`);
          if (tlv.tag & 0x20) walk(tlv.contentStart, tlv.end);
          at = tlv.end;
        }
      };
      walk(0, der.length);
      assert.ok(new X509Certificate(result.data).verify(new X509Certificate(issuer.cert).publicKey));
    }
    await assertFinal(
      (await signFinalCertificate(params(issuer, precert, sctList([65486])))).data,
      precert,
      issuer,
      sctList([65486]),
      false,
    );
  });

  describe('backends', () => {
    test('the openssl backend signs it', async () => {
      const issuer = ca('ML-DSA-44');
      const precert = await precertificate(issuer);
      const result = await signFinalCertificate(params(issuer, precert), { backends: ['openssl'] });
      assert.equal(result.backend, 'openssl');
      await assertFinal(result.data, precert, issuer, list);
    });

    test('an algorithm forced to OpenSSL goes to the openssl backend, not a whole-operation fallback', async () => {
      const issuer = ca('RSA-2048');
      const precert = await precertificate(issuer);
      for (const forceOpenSSL of [true, ['sha256WithRSAEncryption']] as const) {
        const result = await createSigner({ forceOpenSSL }).signFinalCertificate(params(issuer, precert));
        assert.equal(result.backend, 'openssl');
        await assertFinal(result.data, precert, issuer, list);
      }
      // only the openssl backends, and none of them allowed: refused
      await assert.rejects(
        createSigner({ forceOpenSSL: true, backends: ['software'] }).signFinalCertificate(params(issuer, precert)),
        (err) => err instanceof UnsupportedError && err.step === 'check allowlist',
      );
    });

    test("refuses a KMS key the KMS backend can't sign when there is no PKCS#11 module to sign through", async () => {
      const issuer = ca('EC-P256');
      const precert = await precertificate(issuer);
      const kms = new FakeKms();
      const keyVersion = kms.add(issuer.key, issuer.password);
      await assert.rejects(
        signFinalCertificate(
          { ...params(issuer, precert), key: '', kms: { keyVersion } },
          { kms: () => Promise.resolve(kms) },
        ),
        (err) => err instanceof UnsupportedError && err.message.includes('ecdsa-with-SHA256 with kms keys'),
      );
      assert.equal(kms.requests.length, 0);
    });

    test('a KMS key signs it (stand-in client)', async () => {
      const issuer = ca('RSA-2048');
      const precert = await precertificate(issuer);
      const kms = new FakeKms();
      const keyVersion = kms.add(issuer.key, issuer.password);
      const settings: KeySettings = { kms: () => Promise.resolve(kms) };
      const result = await signFinalCertificate({ ...params(issuer, precert), key: '', kms: { keyVersion } }, settings);
      assert.equal(result.backend, 'kms');
      assert.deepEqual(kms.requests.at(-1), { name: keyVersion, digest: 'sha256' });
      await assertFinal(result.data, precert, issuer, list);
    });

    test("refuses ML-DSA on a PKCS#11 token, which can't sign it (no token needed: refused before loading)", async () => {
      const issuer = ca('ML-DSA-44');
      const precert = await precertificate(issuer);
      const pkcs11 = { uri: 'pkcs11:token=none;id=%01;type=private', pin: '0000', modulePath: '/nonexistent/lib.so' };
      await assert.rejects(
        signFinalCertificate({ ...params(issuer, precert), key: '', pkcs11 }, { pkcs11: new Pkcs11Sessions() }),
        (err) =>
          err instanceof UnsupportedError && err.message.includes('ML-DSA-44 with pkcs11 or openssl-pkcs11 keys'),
      );
    });

    describe('PKCS#11', { skip }, () => {
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
      test("a KMS key the KMS backend can't sign goes through its PKCS#11 module with OpenSSL (SoftHSM standing in)", async () => {
        for (const [name, forceOpenSSL] of [
          ['EC-P256', undefined],
          ['RSA-2048', ['sha256WithRSAEncryption']],
        ] as const) {
          const issuer = ca(name);
          const precert = await precertificate(issuer);
          const kms = new FakeKms();
          const keyVersion = kms.add(issuer.key, issuer.password);
          const pkcs11 = await token.importKey(issuer.key, issuer.password);
          const result = await signFinalCertificate(
            { ...params(issuer, precert), key: '', pkcs11, kms: { keyVersion } },
            { kms: () => Promise.resolve(kms), pkcs11: sessions, ...(forceOpenSSL ? { forceOpenSSL } : {}) },
          );
          assert.equal(result.backend, 'openssl-pkcs11', name);
          await assertFinal(result.data, precert, issuer, list);
        }
      });

      for (const backend of ['pkcs11', 'openssl-pkcs11']) {
        for (const name of ['RSA-2048', 'EC-P384']) {
          test(`${backend} ${name}`, async () => {
            const issuer = ca(name);
            const precert = await precertificate(issuer, name === 'EC-P384' ? 'sha384' : undefined);
            const pkcs11 = await token.importKey(issuer.key, issuer.password);
            const result = await signFinalCertificate(
              { ...params(issuer, precert), key: '', pkcs11 },
              { backends: [backend], pkcs11: sessions },
            );
            assert.equal(result.backend, backend);
            await assertFinal(result.data, precert, issuer, list);
          });
        }
      }
    });
  });

  describe('refuses', () => {
    const refused = async (p: Promise<unknown>, step: string, message: RegExp) =>
      assert.rejects(p, (err) => {
        assert.ok(err instanceof SignerError, String(err));
        assert.equal(err.step, step);
        assert.match(err.message, message);
        return true;
      });

    test('something that is not a certificate', async () => {
      const issuer = ca('RSA-2048');
      await refused(signFinalCertificate(params(issuer, csr)), 'parse precertificate', /no CERTIFICATE PEM/);
      await refused(
        signFinalCertificate({ ...params(issuer, await precertificate(issuer)), ca: 'x' }),
        'parse CA certificate',
        /no CERTIFICATE PEM/,
      );
      // a PEM OpenSSL can't read as a certificate
      const garbage = '-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n';
      await refused(signFinalCertificate(params(issuer, garbage)), 'parse precertificate', /not a certificate/);
    });

    test('a certificate without the poison: an ordinary certificate', async () => {
      const issuer = ca('RSA-2048');
      const { data } = await caSignCSR({
        csr,
        ca: issuer.cert,
        key: issuer.key,
        password: issuer.password,
        options: {},
      });
      await refused(signFinalCertificate(params(issuer, data)), 'check precertificate', /not exactly one poison/);
    });

    test('a precertificate of another CA, or of another key with the same name', async () => {
      const issuer = ca('RSA-2048');
      const precert = await precertificate(issuer);
      await refused(
        signFinalCertificate({ ...params(issuer, precert), ca: ca('EC-P256').cert }),
        'check precertificate',
        /issuer is not the CA/,
      );
      const other = ca('RSA-2048 other key');
      await refused(
        signFinalCertificate({ ...params(other, precert) }),
        'verify precertificate',
        /not signed by the CA's key/,
      );
    });

    test("a key that isn't the CA's", async () => {
      const issuer = ca('RSA-2048');
      const other = ca('RSA-2048 other key');
      const precert = await precertificate(issuer);
      await refused(
        signFinalCertificate({ ...params(issuer, precert), key: other.key, password: other.password }),
        'load CA key',
        /don't match/,
      );
    });

    for (const [what, change, message, step = 'check precertificate'] of [
      [
        'two poison extensions',
        (c: Certificate) => c.tbsCertificate.extensions?.push(c.tbsCertificate.extensions.at(-1)!),
        /not exactly one poison/,
      ],
      [
        'a poison that is not critical',
        (c: Certificate) => {
          const poison = c.tbsCertificate.extensions?.find((e) => e.extnID === POISON);
          if (poison) poison.critical = false;
        },
        /not critical/,
      ],
      [
        'a poison that is not NULL',
        (c: Certificate) => {
          const poison = c.tbsCertificate.extensions?.find((e) => e.extnID === POISON);
          if (poison) poison.extnValue = new OctetString(new Uint8Array([4, 0]));
        },
        /not NULL/,
      ],
      [
        'an SCT list already',
        (c: Certificate) =>
          c.tbsCertificate.extensions?.push(
            new Extension({ extnID: SCT_LIST, extnValue: new OctetString(sctList([8])) }),
          ),
        /SCT list already/,
      ],
      [
        'a version 1 certificate',
        (c: Certificate) => {
          c.tbsCertificate.version = Version.v1;
          c.tbsCertificate.extensions = undefined;
        },
        /not a version 3 certificate/,
        'parse precertificate',
      ],
    ] as const) {
      test(what, async () => {
        const issuer = ca('RSA-2048');
        const precert = resign(await precertificate(issuer), issuer, change);
        await refused(signFinalCertificate(params(issuer, precert)), step, message);
      });
    }

    test('a precertificate that is not DER, before signing anything', async () => {
      const issuer = ca('RSA-2048');
      const der = new Uint8Array(new X509Certificate(await precertificate(issuer)).raw);
      const [tbs, algorithm] = readChildren(der, readTlv(der, 0, der.length, 't'), 't');
      assert.ok(tbs && algorithm);
      // the serial INTEGER with a long-form length, which OpenSSL reads
      const fields = readChildren(der, tbs, 't').map((f, i) => {
        const content = der.subarray(f.contentStart, f.end);
        return i === 1 ? Uint8Array.from([0x02, 0x81, content.length, ...content]) : der.subarray(f.start, f.end);
      });
      const newTbs = encodeTlv(0x30, ...fields);
      const signature = sign('sha256', newTbs, createPrivateKey({ key: issuer.key, passphrase: issuer.password }));
      const cert = encodeTlv(
        0x30,
        newTbs,
        der.subarray(algorithm.start, algorithm.end),
        encodeTlv(0x03, Uint8Array.of(0), signature),
      );
      let signed = false;
      const key = { key: '', kms: { keyVersion: 'k' } };
      const kms = () => Promise.resolve({ asymmetricSign: () => ((signed = true), Promise.reject(new Error('no'))) });
      await refused(
        signFinalCertificate({ ...params(issuer, new X509Certificate(Buffer.from(cert)).toString()), ...key }, { kms }),
        'check precertificate',
        /it is not DER/,
      );
      assert.equal(signed, false);
    });

    test('signature algorithms inside and outside the TBS that differ', async () => {
      const issuer = ca('RSA-2048');
      const precert = resign(await precertificate(issuer), issuer, (c) => {
        c.signatureAlgorithm.algorithm = '1.2.840.113549.1.1.12';
      });
      // OpenSSL itself refuses the signature, before the library compares the algorithms
      await assert.rejects(signFinalCertificate(params(issuer, precert)), SignerError);
    });

    for (const [what, bytes, message] of [
      ['an SCT list that is not an OCTET STRING', Uint8Array.from([0x30, 0x02, 0x00, 0x00]), /not a DER OCTET STRING/],
      [
        'a long-form length where a short one fits',
        Uint8Array.from([0x04, 0x81, 0x02, 0x00, 0x00]),
        /not a DER OCTET STRING/,
      ],
      ['trailing bytes', Uint8Array.from([...sctList([8]), 0]), /not a DER OCTET STRING/],
      ['a wrong list length', Uint8Array.from([0x04, 0x04, 0x00, 0x03, 0x00, 0x00]), /the list length is wrong/],
      ['an empty list', Uint8Array.from([0x04, 0x02, 0x00, 0x00]), /the list is empty/],
      ['an empty SCT', Uint8Array.from([0x04, 0x04, 0x00, 0x02, 0x00, 0x00]), /an SCT length is wrong/],
      [
        'an SCT longer than the list',
        Uint8Array.from([0x04, 0x05, 0x00, 0x03, 0x00, 0x05, 0x01]),
        /an SCT length is wrong/,
      ],
      ['nothing', new Uint8Array(0), /truncated DER/],
    ] as const) {
      test(what, async () => {
        const issuer = ca('RSA-2048');
        await refused(
          signFinalCertificate(params(issuer, await precertificate(issuer), bytes)),
          'check SCT list',
          message,
        );
      });
    }

    test('RSA-PSS, which no PKIaaS.io CA signs with', async () => {
      const issuer = ca('RSA-2048');
      const precert = await opensslPrecert(
        issuer,
        csr,
        [`${POISON} = critical,ASN1:NULL`],
        ['-sigopt', 'rsa_padding_mode:pss'],
      );
      await assert.rejects(
        signFinalCertificate(params(issuer, precert)),
        (err) =>
          err instanceof UnsupportedError &&
          err.step === 'parse precertificate' &&
          err.message.includes('1.2.840.113549.1.1.10'),
      );
    });

    test('Ed25519, which no PKIaaS.io CA has', async () => {
      const issuer = await createCA({ name: 'Ed25519', type: 'ed25519', pqc: false });
      const precert = await opensslPrecert(issuer, csr, [`${POISON} = critical,ASN1:NULL`]);
      await assert.rejects(signFinalCertificate(params(issuer, precert)), UnsupportedError);
    });
  });

  test('never puts the key, passphrase or SCT list into errors', async () => {
    const issuer = ca('RSA-2048');
    const precert = await precertificate(issuer);
    await assert.rejects(signFinalCertificate({ ...params(issuer, precert), password: 'wrong' }), (err: Error) => {
      assert.equal((err as SignerError).step, 'load CA key');
      assert.ok(!err.message.includes(issuer.password) && !err.message.includes('wrong'));
      return true;
    });
  });

  test('the DER walker refuses an indefinite length and children that overrun their parent', () => {
    assert.throws(() => readTlv(Uint8Array.from([0x30, 0x80, 0, 0]), 0, 4, 't'), /invalid DER length/);
    const der = Uint8Array.from([0x30, 0x02, 0x04, 0x02, 0x00, 0x00]);
    assert.throws(() => readChildren(der, readTlv(der, 0, der.length, 't'), 't'), /truncated DER/);
  });
});
