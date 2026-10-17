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
  /** a key on a PKCS#11 token instead of `key`, as the IoT HSM agent passes it */
  pkcs11?: Pkcs11KeyRef | false | null;
  /**
   * a Google Cloud KMS key, signed with the KMS API (ADR 0003). The agent passes it beside `pkcs11`
   * (libkmsp11), which the OpenSSL fallback keeps using.
   */
  kms?: { keyVersion: string } | null;
}

/** A private key on a PKCS#11 token. */
export interface Pkcs11KeyRef {
  /** RFC 7512 URI, e.g. `pkcs11:serial=0123;id=%01;type=private` */
  uri: string;
  /** the user PIN */
  pin?: string;
  /** the PKCS#11 module, e.g. /usr/lib/x86_64-linux-gnu/libykcs11.so */
  modulePath: string;
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
  /** the PKCS#11 module node-openssl-cert2 loads through pkcs11-provider; the agent sets it beside `pkcs11` */
  module?: string;
}

export interface SignResult {
  /** the certificate, PEM */
  data: string;
  /** the serial number, upper-case hex */
  serial: string;
}
