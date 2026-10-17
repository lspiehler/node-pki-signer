// A SoftHSM token for the PKCS#11 backends' tests, in a temporary directory: the corpus CA keys are
// imported into it so node-openssl-cert2 (openssl ca with pkcs11-provider) and the library sign with
// the same key.
import { execFile } from 'node:child_process';
import { createPrivateKey, randomBytes } from 'node:crypto';
import { access, mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { promisify } from 'node:util';
import type { Pkcs11KeyRef } from '../../src/options.ts';

const run = promisify(execFile);

const modulePaths = ['/usr/lib/softhsm/libsofthsm2.so', '/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so'];
const providerPath = '/usr/lib/x86_64-linux-gnu/ossl-modules/pkcs11.so';

/** The SoftHSM module, or why the PKCS#11 tests can't run here. */
export async function findSoftHSM(): Promise<{ modulePath: string } | { missing: string }> {
  for (const modulePath of modulePaths) {
    try {
      await access(modulePath);
      await access(providerPath);
      return { modulePath };
    } catch {
      // try the next path
    }
  }
  return { missing: `SoftHSM (${modulePaths.join(' or ')}) and pkcs11-provider (${providerPath})` };
}

export interface Token {
  /** imports a CA's PEM key once and returns its reference */
  importKey(pem: string, passphrase: string): Promise<Pkcs11KeyRef>;
  remove(): Promise<void>;
}

/** Initializes a token; sets SOFTHSM2_CONF for this process, so call it before loading SoftHSM. */
export async function createToken(modulePath: string): Promise<Token> {
  const dir = await mkdtemp(join(tmpdir(), 'pki-signer-softhsm-'));
  await mkdir(join(dir, 'tokens'));
  await writeFile(join(dir, 'softhsm2.conf'), `directories.tokendir = ${join(dir, 'tokens')}\nlog.level = ERROR\n`);
  process.env.SOFTHSM2_CONF = join(dir, 'softhsm2.conf');
  const label = 'signer-test';
  const pin = randomBytes(6).toString('hex');
  await run('softhsm2-util', ['--init-token', '--free', '--label', label, '--pin', pin, '--so-pin', pin]);
  const imported = new Map<string, Promise<Pkcs11KeyRef>>();
  let queue = Promise.resolve();
  return {
    importKey(pem, passphrase) {
      let ref = imported.get(pem);
      if (!ref) {
        const id = (imported.size + 1).toString(16).padStart(2, '0');
        const file = join(dir, `${id}.pem`);
        const key = createPrivateKey({ key: pem, passphrase }).export({ type: 'pkcs8', format: 'pem' });
        // softhsm2-util writes the token's files, so one import at a time
        const done = queue.then(async () => {
          await writeFile(file, key, { mode: 0o600 });
          await run('softhsm2-util', [
            '--import',
            file,
            '--token',
            label,
            '--label',
            `ca${id}`,
            '--id',
            id,
            '--pin',
            pin,
          ]);
          await rm(file);
        });
        queue = done.catch(() => undefined);
        ref = done.then(() => ({ uri: `pkcs11:token=${label};id=%${id};type=private`, pin, modulePath }));
        imported.set(pem, ref);
      }
      return ref;
    },
    remove: () => rm(dir, { recursive: true, force: true }),
  };
}
