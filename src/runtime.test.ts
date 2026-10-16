// Checks that this Node runtime can sign with every CA key type PKIaaS.io offers, which the native
// signing path depends on: RSA, EC, ML-DSA and SLH-DSA through node:crypto (OpenSSL >= 3.5).
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign, verify, type KeyObject } from 'node:crypto';
import { describe, test } from 'node:test';

const message = Buffer.from('to-be-signed');

function roundTrip(privateKey: KeyObject, publicKey: KeyObject, hash: string | null) {
  const signature = sign(hash, message, privateKey);
  assert.ok(verify(hash, message, publicKey, signature), 'signature verifies');
}

describe('runtime', () => {
  test('bundles OpenSSL 3.5 or newer', () => {
    const [major = 0, minor = 0] = process.versions.openssl.split('.').map(Number);
    assert.ok(major > 3 || (major === 3 && minor >= 5), `OpenSSL ${process.versions.openssl}`);
  });

  for (const modulusLength of [2048, 4096]) {
    test(`signs with RSA ${modulusLength}`, () => {
      const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength });
      roundTrip(privateKey, publicKey, 'sha256');
    });
  }

  for (const namedCurve of ['prime256v1', 'secp384r1', 'secp521r1']) {
    test(`signs with EC ${namedCurve}`, () => {
      const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve });
      roundTrip(privateKey, publicKey, 'sha256');
    });
  }

  for (const type of ['ml-dsa-44', 'ml-dsa-65', 'ml-dsa-87'] as const) {
    test(`signs with ${type}`, () => {
      const { privateKey, publicKey } = generateKeyPairSync(type);
      roundTrip(privateKey, publicKey, null);
    });
  }

  // all 12 SLH-DSA parameter sets the platform offers
  const slhDsa = ['sha2', 'shake'].flatMap((hash) =>
    ['128', '192', '256'].flatMap((bits) => ['s', 'f'].map((speed) => `slh-dsa-${hash}-${bits}${speed}`)),
  );
  for (const type of slhDsa) {
    test(`signs with ${type}`, () => {
      // node:crypto's overloads list each key type literally; the parameter sets above are all valid
      const { privateKey, publicKey } = generateKeyPairSync(type as 'slh-dsa-sha2-128s');
      roundTrip(privateKey, publicKey, null);
    });
  }
});
