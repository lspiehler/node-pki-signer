// The parts of node-openssl-cert2 (CommonJS, untyped) that the fallback and the differential harness call.
declare module 'node-openssl-cert2' {
  // errors are openssl's stderr, or an Error from writing its temporary files
  type Callback<T> = (err: false | string | Error, result: T) => void;

  // `files.config` is the generated openssl.cnf
  interface CASignCSRResult {
    data: string | null;
    serial?: string;
    command: string[] | null;
    files?: { config: string };
  }

  class NodeOpenSSL {
    constructor(options?: { binpath?: string });
    x509: {
      CASignCSR(
        params: { csr: string; options: object; ca: string; key: string; password?: string; pkcs11?: unknown },
        callback: Callback<CASignCSRResult | false>,
      ): void;
    };
    csr: {
      parse(params: { csr: string; verify: boolean }, callback: Callback<{ data: Record<string, unknown> }>): void;
    };
  }

  export = NodeOpenSSL;
}
