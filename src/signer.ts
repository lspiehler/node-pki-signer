// The drop-in for node-openssl-cert2's x509.CASignCSR (ADR 0001): signs natively when it can and
// hands the whole operation to node-openssl-cert2 when it can't, reporting every fallback.
import NodeOpenSSL from 'node-openssl-cert2';
import { caSignCSR } from './ca-sign-csr.ts';
import { SignerError, UnsupportedError } from './errors.ts';
import type { SignParams, SignResult } from './options.ts';

/** Why an operation went to OpenSSL. Never contains keys, passphrases or CSRs. */
export interface Fallback {
  /** e.g. 'CASignCSR' */
  operation: string;
  /** the native step that couldn't go on, e.g. 'load CA key' */
  step: string;
  /** e.g. 'load CA key: PKCS#11 keys' */
  reason: string;
}

export interface SignerSettings {
  /** the openssl binary for the fallback (node-openssl-cert2's `binpath`); `openssl` on the PATH by default */
  binpath?: string;
  /** signature algorithms always signed with OpenSSL, e.g. ['ML-DSA-65']; true for every algorithm */
  forceOpenSSL?: boolean | readonly string[];
  /** called for every fallback, e.g. to write it to the CA's log; a console.warn by default */
  onFallback?: (fallback: Fallback) => void;
}

/** Which path signed: the library itself or node-openssl-cert2. */
export type SignedBy = 'native' | 'openssl';

/** What x509.CASignCSR passes its callback: node-openssl-cert2's result, plus who signed. */
export interface CASignCSRResult {
  data: string | null;
  serial?: string;
  command: string[] | null;
  files?: { config: string };
  signedBy?: SignedBy;
}

export interface Signer {
  /** Signs a CSR natively or, failing that, with OpenSSL. Rejects with a SignerError naming the step. */
  caSignCSR(params: SignParams): Promise<SignResult & { signedBy: SignedBy }>;
  /** The same, called exactly like node-openssl-cert2's: errors and results as it passes them. */
  x509: {
    CASignCSR(
      params: SignParams,
      callback: (err: false | string | Error, result: CASignCSRResult | false) => void,
    ): void;
  };
}

const message = (err: unknown) => (err instanceof Error ? err.message : String(err).trim());

/** A signer with its fallback settings; create one per process and reuse it. */
export function createSigner(settings: SignerSettings = {}): Signer {
  const openssl = new NodeOpenSSL(settings.binpath ? { binpath: settings.binpath } : undefined);
  const force = settings.forceOpenSSL ?? false;
  const onFallback =
    settings.onFallback ??
    ((fallback: Fallback) => {
      console.warn(`node-pki-signer: ${fallback.operation} fell back to OpenSSL: ${fallback.reason}`);
    });

  // the native certificate, or why the request must go to OpenSSL; refusals reject
  async function native(params: SignParams): Promise<{ result: SignResult } | { fallback: Fallback }> {
    const operation = 'CASignCSR';
    if (force === true) {
      return {
        fallback: {
          operation,
          step: 'check allowlist',
          reason: 'check allowlist: every algorithm is set to sign with OpenSSL',
        },
      };
    }
    try {
      return { result: await caSignCSR(params, { forceOpenSSL: force === false ? [] : force }) };
    } catch (err) {
      if (err instanceof UnsupportedError) return { fallback: { operation, step: err.step, reason: err.message } };
      // a refusal of the request itself, which OpenSSL would refuse too (the differential harness checks)
      if (err instanceof SignerError) throw err;
      // a bug in the native path mustn't stop issuance
      return {
        fallback: { operation, step: 'native signer', reason: `native signer: unexpected error: ${message(err)}` },
      };
    }
  }

  return {
    async caSignCSR(params) {
      const outcome = await native(params);
      if ('result' in outcome) return { ...outcome.result, signedBy: 'native' };
      onFallback(outcome.fallback);
      return new Promise((resolve, reject) => {
        openssl.x509.CASignCSR(params, (err, result) => {
          if (err || !result || !result.data || !result.serial) {
            reject(new SignerError('sign with OpenSSL', err ? message(err) : 'no certificate'));
          } else {
            resolve({ data: result.data, serial: result.serial, signedBy: 'openssl' });
          }
        });
      });
    },
    x509: {
      CASignCSR(params, callback) {
        native(params).then(
          (outcome) => {
            if ('result' in outcome) {
              callback(false, { ...outcome.result, command: null, signedBy: 'native' });
              return;
            }
            onFallback(outcome.fallback);
            openssl.x509.CASignCSR(params, (err, result) => {
              callback(err, result && { ...result, signedBy: 'openssl' });
            });
          },
          (err: unknown) => {
            callback(err instanceof Error ? err : new Error(message(err)), { command: null, data: null });
          },
        );
      },
    },
  };
}
