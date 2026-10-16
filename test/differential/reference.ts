// The reference signing path: node-openssl-cert2's x509.CASignCSR, exactly as PKIaaS.io and the
// IoT HSM agent call it today (one `openssl ca` process per certificate).
import NodeOpenSSL from 'node-openssl-cert2';

const openssl2 = new NodeOpenSSL();

const message = (err: string | Error) => (err instanceof Error ? err.message : err.trim());

/** The parameters pkiaas passes to x509.CASignCSR (lib/ca/signCSR.js) and a candidate must accept. */
export interface SignParams {
  csr: string;
  options: SignOptions;
  /** issuer certificate, PEM */
  ca: string;
  /** issuer private key, encrypted PKCS#8 PEM */
  key: string;
  password: string;
}

/** The options object pkiaas builds in lib/template/processTemplate.js; see pkiaas-options.ts. */
export interface SignOptions {
  hash?: string;
  subject?: Record<string, string | string[]> | false | null;
  extensions?: Record<string, unknown>;
  startdate?: Date;
  enddate?: Date;
  days?: number;
}

/** Signs a CSR and returns the certificate PEM, like `crt.data` in pkiaas. */
export type Signer = (params: SignParams) => Promise<string>;

export const referenceSigner: Signer = (params) =>
  new Promise((resolve, reject) => {
    // CASignCSR fills in defaults on the options object, so give it a copy
    const options = structuredClone(params.options);
    openssl2.x509.CASignCSR({ ...params, options }, (err, result) => {
      if (err) {
        reject(new Error(`reference CASignCSR: ${message(err)}`));
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
