// Signs the library's to-be-signed bytes with the system openssl (ADR 0001, first fallback level),
// for algorithms OpenSSL supports before node:crypto or pkcs11js do. `openssl dgst -sign`, because
// `pkeyutl` can't sign ML-DSA or SLH-DSA input from a pipe (ADR 0003). The key and passphrase go
// through pipes, never files or arguments.
import { spawn } from 'node:child_process';
import { signatureHash } from './algorithms.ts';
import { SignerError } from './errors.ts';
import type { Pkcs11KeyRef } from './options.ts';
import { parsePkcs11URI } from './pkcs11-key.ts';
import type { SigningKey } from './signing-key.ts';

/** The private key OpenSSL signs with: a PEM, or a key on a PKCS#11 token through pkcs11-provider. */
export type OpenSSLKeySource = { pem: string; passphrase?: string | undefined } | { pkcs11: Pkcs11KeyRef };

/**
 * A SigningKey that runs `openssl dgst -sign` per signature, for `algorithm` (the CA certificate's).
 * `publicKey` is the CA certificate's; the caller verifies each signature against it.
 */
export function opensslKey(
  source: OpenSSLKeySource,
  algorithm: string,
  publicKey: Uint8Array,
  binpath = 'openssl',
): SigningKey {
  const hash = signatureHash(algorithm);
  const digest = hash ? [`-${hash}`] : [];
  const pkcs11 = 'pkcs11' in source ? source.pkcs11 : undefined;
  // openssl reads any other -sign value as a key file, or as an option when it starts with -
  if (pkcs11) parsePkcs11URI(pkcs11.uri);
  const passphrase = pkcs11 ? pkcs11.pin : 'pem' in source ? source.passphrase : undefined;
  // a PEM goes in on fd 4 through a pipe bash opens, since openssl can't open the socket Node passes
  const [command, args] = pkcs11
    ? [binpath, ['dgst', '-binary', ...digest, '-sign', pkcs11.uri, '-provider', 'pkcs11', '-provider', 'default']]
    : ['bash', ['-c', 'exec "$1" dgst -binary "${@:2}" -sign <(cat <&4) -passin fd:3', 'bash', binpath, ...digest]];
  return {
    backend: pkcs11 ? 'openssl-pkcs11' : 'openssl',
    algorithm,
    publicKey: () => Promise.resolve(publicKey),
    sign(tbs) {
      return new Promise((resolve, reject) => {
        const child = spawn(command, pkcs11 ? [...args, '-passin', 'fd:3'] : args, {
          stdio: ['pipe', 'pipe', 'pipe', 'pipe', 'pipe'],
          env: pkcs11 ? { ...process.env, PKCS11_PROVIDER_MODULE: pkcs11.modulePath } : process.env,
        });
        const out: Buffer[] = [];
        let stderr = '';
        child.stdout.on('data', (chunk: Buffer) => out.push(chunk));
        child.stderr.on('data', (chunk: Buffer) => (stderr += chunk.toString()));
        // openssl may exit before reading everything; its exit status says why
        for (const stream of child.stdio.slice(0, 5)) stream?.on('error', () => undefined);
        child.on('error', (err) => {
          reject(new SignerError('openssl dgst', err.message));
        });
        // pkcs11-provider can crash unloading a module that uses OpenSSL itself (SoftHSM, libkmsp11)
        // after the signature is out, which the caller verifies anyway
        child.on('close', (code, signal) => {
          if ((code === 0 || signal === 'SIGSEGV') && out.length) {
            resolve(new Uint8Array(Buffer.concat(out)));
          } else {
            // openssl's first line names the failure; the key and passphrase never reach stderr
            reject(
              new SignerError('openssl dgst', (stderr.split('\n')[0] ?? '') || (signal ?? `exit code ${String(code)}`)),
            );
          }
        });
        const [stdin, , , pass, key] = child.stdio as unknown as NodeJS.WritableStream[];
        pass?.end(`${passphrase ?? ''}\n`);
        key?.end('pem' in source ? source.pem : '');
        stdin?.end(tbs);
      });
    },
  };
}
