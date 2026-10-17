// What the live tests sign with a real key that may be a production CA's: certificates from a
// throwaway issuer certificate that carries the key's public key under a test name, valid for an hour.
import { join } from 'node:path';
import type { SignParams } from '../../src/index.ts';
import { caKeyCases } from '../differential/corpus.ts';
import { caKeySpecs, generateKey, withFiles } from '../differential/fixtures.ts';
import { openssl } from '../differential/openssl.ts';

/** An issuer certificate for `publicKey` (PEM) under a test name, signed by a throwaway key. */
export async function testIssuer(publicKey: string, name: string): Promise<string> {
  const rsa = caKeySpecs.find((s) => s.name === 'RSA-2048');
  if (!rsa) throw new Error('no RSA-2048 key spec');
  const { privateKey } = await generateKey(rsa);
  const ext = [
    '[ ca ]',
    'basicConstraints = critical, CA:true',
    'keyUsage = critical, digitalSignature, keyCertSign, cRLSign',
    'subjectKeyIdentifier = hash',
  ].join('\n');
  return withFiles({ 'throwaway.key': privateKey, 'key.pub': publicKey, 'ext.cnf': ext }, (dir) =>
    openssl([
      'x509',
      '-new',
      '-key',
      join(dir, 'throwaway.key'),
      '-force_pubkey',
      join(dir, 'key.pub'),
      '-subj',
      `/C=US/O=PKIaaS Test/CN=${name}`,
      '-days',
      '1',
      '-extfile',
      join(dir, 'ext.cnf'),
      '-extensions',
      'ca',
    ]),
  );
}

/** A web server certificate request to `issuer`, valid for an hour, without the issuer's key. */
export async function testRequest(issuer: string, hash: string): Promise<SignParams> {
  const c = caKeyCases.find((c) => c.spec.name === 'RSA-2048' && c.hash === 'sha256');
  if (!c) throw new Error('no RSA-2048 sha256 corpus case');
  const built = await c.build();
  const now = Date.now();
  return {
    ...built,
    ca: issuer,
    key: '',
    password: '',
    options: {
      ...built.options,
      hash,
      startdate: new Date(now - 5 * 60 * 1000),
      enddate: new Date(now + 60 * 60 * 1000),
    },
  };
}

/** `openssl verify` of a certificate from `issuer`, which isn't self-signed, so only as a partial chain. */
export function verifyPartialChain(cert: string, issuer: string): Promise<string> {
  return withFiles({ 'ca.pem': issuer, 'cert.pem': cert }, (dir) =>
    openssl(['verify', '-partial_chain', '-CAfile', join(dir, 'ca.pem'), join(dir, 'cert.pem')]),
  );
}
