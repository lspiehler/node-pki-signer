// The reference signing path: node-openssl-cert2's x509.CASignCSR, exactly as PKIaaS.io and the
// IoT HSM agent call it today (one `openssl ca` process per certificate).
import NodeOpenSSL from 'node-openssl-cert2';
import type { SignOptions, SignParams } from '../../src/options.ts';

const openssl2 = new NodeOpenSSL();

const message = (err: string | Error) => (err instanceof Error ? err.message : err.trim());

// the parameters pkiaas passes to x509.CASignCSR (lib/ca/signCSR.js), which a candidate must accept
export type { SignOptions, SignParams } from '../../src/options.ts';

/** Signs a CSR and returns the certificate PEM, like `crt.data` in pkiaas. */
export type Signer = (params: SignParams) => Promise<string>;

export const referenceSigner: Signer = (params) =>
  new Promise((resolve, reject) => {
    // CASignCSR fills in defaults on the options object, so give it a copy
    const options = structuredClone(params.options);
    openssl2.x509.CASignCSR({ ...params, options }, (err, result) => {
      // with PKCS#11 keys, openssl ca can crash unloading the module after it wrote the certificate
      // (pkcs11-provider with SoftHSM; the agent retries libkmsp11's): the certificate is what counts
      const data = result ? result.data : null;
      if (params.pkcs11 && String(err).includes('SIGSEGV') && data?.includes('-----END CERTIFICATE-----')) {
        resolve(data);
      } else if (err || !result || !result.data) {
        reject(new Error(`reference CASignCSR: ${err ? message(err) : 'no certificate'}`));
      } else {
        resolve(result.data);
      }
    });
  });

/** Parses a CSR into options the way pkiaas does (lib/csr/parseCSR.js). */
export function parseCSR(csr: string): Promise<SignOptions> {
  return new Promise((resolve, reject) => {
    openssl2.csr.parse({ csr, verify: true }, (err, result) => {
      if (err) {
        reject(new Error(`parse CSR: ${message(err)}`));
      } else {
        resolve(result.data);
      }
    });
  });
}
