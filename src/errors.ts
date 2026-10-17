/** A signing failure, naming the step that failed so callers can log it to the CA's log. */
export class SignerError extends Error {
  readonly step: string;

  constructor(step: string, message: string, options?: ErrorOptions) {
    super(`${step}: ${message}`, options);
    this.name = 'SignerError';
    this.step = step;
  }
}

/**
 * The native path can't build or sign this request yet (ADR 0001), so it must go to OpenSSL.
 * Not a refusal of the request itself: the OpenSSL fallback may well sign it.
 */
export class UnsupportedError extends SignerError {
  constructor(step: string, message: string) {
    super(step, message);
    this.name = 'UnsupportedError';
  }
}
