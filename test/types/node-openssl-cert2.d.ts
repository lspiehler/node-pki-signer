// The parts of node-openssl-cert2 (CommonJS, untyped) that the differential harness calls.
declare module 'node-openssl-cert2' {
  // errors are openssl's stderr, or an Error from writing its temporary files
  type Callback<T> = (err: false | string | Error, result: T) => void;

  class NodeOpenSSL {
    constructor(options?: { binpath?: string });
    x509: {
      CASignCSR(
        params: { csr: string; options: object; ca: string; key: string; password?: string },
        callback: Callback<{ data: string; serial?: string; command: string[] | null }>,
      ): void;
    };
    csr: {
      parse(params: { csr: string; verify: boolean }, callback: Callback<{ data: Record<string, unknown> }>): void;
    };
  }

  export = NodeOpenSSL;
}
