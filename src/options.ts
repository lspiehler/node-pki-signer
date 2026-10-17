/** What node-openssl-cert2's x509.CASignCSR takes, as PKIaaS.io and the IoT HSM agent call it. */
export interface SignParams {
  /** the certificate request, PEM */
  csr: string;
  options: SignOptions;
  /** issuer certificate, PEM */
  ca: string;
  /** issuer private key, PEM (encrypted PKCS#8 in PKIaaS.io) */
  key: string;
  password?: string;
  /** the agent's PKCS#11 key; not signed natively yet */
  pkcs11?: unknown;
}

/** The options object pkiaas builds in lib/template/processTemplate.js. */
export interface SignOptions {
  hash?: string;
  /** the certificate's subject in this order; false or null for an empty subject */
  subject?: Record<string, string | string[]> | false | null;
  extensions?: Record<string, unknown> | null;
  startdate?: Date | string | number;
  enddate?: Date | string | number;
  /** validity from now when there is no startdate; 365 by default */
  days?: number;
}

export interface SignResult {
  /** the certificate, PEM */
  data: string;
  /** the serial number, upper-case hex */
  serial: string;
}
