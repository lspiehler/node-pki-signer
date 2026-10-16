// Issuing CAs and CSRs for the corpus, generated per run: keys with node:crypto, certificates and
// CSRs with the system openssl, the way PKIaaS.io stores them (encrypted PKCS#8, AES-256).
import { generateKeyPair, randomBytes } from 'node:crypto';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { promisify } from 'node:util';
import { openssl } from './openssl.ts';

const generate = promisify(generateKeyPair) as (
  type: string,
  options: object,
) => Promise<{ privateKey: string; publicKey: string }>;

/** A key type as `generateKeyPair` names it, with its options. */
export interface KeySpec {
  name: string;
  type: string;
  options?: object;
  pqc: boolean;
}

const slhDsa = ['sha2', 'shake'].flatMap((hash) =>
  ['128', '192', '256'].flatMap((bits) => ['s', 'f'].map((speed) => `slh-dsa-${hash}-${bits}${speed}`)),
);

/** Every CA key type PKIaaS.io offers (lib/ca/createCA.js). */
export const caKeySpecs: KeySpec[] = [
  { name: 'RSA-2048', type: 'rsa', options: { modulusLength: 2048 }, pqc: false },
  { name: 'RSA-4096', type: 'rsa', options: { modulusLength: 4096 }, pqc: false },
  { name: 'EC-P256', type: 'ec', options: { namedCurve: 'prime256v1' }, pqc: false },
  { name: 'EC-P384', type: 'ec', options: { namedCurve: 'secp384r1' }, pqc: false },
  { name: 'EC-P521', type: 'ec', options: { namedCurve: 'secp521r1' }, pqc: false },
  ...['ml-dsa-44', 'ml-dsa-65', 'ml-dsa-87'].map((type) => ({ name: type.toUpperCase(), type, pqc: true })),
  ...slhDsa.map((type) => ({ name: type.toUpperCase(), type, pqc: true })),
];

export async function generateKey(spec: KeySpec, passphrase?: string) {
  return generate(spec.type, {
    ...spec.options,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: passphrase
      ? { type: 'pkcs8', format: 'pem', cipher: 'aes-256-cbc', passphrase }
      : { type: 'pkcs8', format: 'pem' },
  });
}

/** Writes PEM files into a temporary directory for the duration of `run`. */
async function withFiles<T>(files: Record<string, string>, run: (dir: string) => Promise<T>): Promise<T> {
  const dir = await mkdtemp(join(tmpdir(), 'pki-signer-fixture-'));
  try {
    await Promise.all(Object.entries(files).map(([name, data]) => writeFile(join(dir, name), data, { mode: 0o600 })));
    return await run(dir);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

export interface IssuingCA {
  spec: KeySpec;
  cert: string;
  key: string;
  password: string;
  /** what processOptions needs to build AIA, CDP and policy URLs */
  ca: { publicid: string; name: string; policy_oid: string };
}

/** A self-signed issuing CA, like createCA.js makes (`req -x509`). */
export async function createCA(spec: KeySpec): Promise<IssuingCA> {
  const password = randomBytes(15).toString('base64url');
  const { privateKey } = await generateKey(spec, password);
  const name = `Harness ${spec.name} CA`;
  const cert = await withFiles({ 'ca.key': privateKey }, (dir) =>
    openssl(
      [
        'req',
        '-x509',
        '-new',
        '-key',
        join(dir, 'ca.key'),
        '-passin',
        'stdin',
        '-days',
        '3650',
        '-utf8',
        '-subj',
        `/C=US/O=PKIaaS Test/CN=${name}`,
        '-addext',
        'basicConstraints=critical,CA:true',
        '-addext',
        'keyUsage=critical,digitalSignature,keyCertSign,cRLSign',
      ],
      password,
    ),
  );
  return {
    spec,
    cert,
    key: privateKey,
    password,
    ca: { publicid: 'Ab3dE6gH9j', name, policy_oid: '1.3.6.1.4.1.57264.1.1' },
  };
}

/** A CSR for a fresh key: `subject` in openssl -subj form, `config` lines for the [req_ext] section. */
export async function createCSR(spec: KeySpec, subject: string, config: string[] = [], attributes: string[] = []) {
  const { privateKey } = await generateKey(spec);
  const cnf = [
    '[ req ]',
    'distinguished_name = dn',
    'req_extensions = req_ext',
    ...(attributes.length ? ['attributes = req_attributes'] : []),
    '[ dn ]',
    '[ req_ext ]',
    ...config,
    ...(attributes.length ? ['[ req_attributes ]', ...attributes] : []),
  ].join('\n');
  return withFiles({ 'csr.key': privateKey, 'csr.cnf': cnf }, (dir) =>
    openssl(['req', '-new', '-key', join(dir, 'csr.key'), '-config', join(dir, 'csr.cnf'), '-utf8', '-subj', subject]),
  );
}
