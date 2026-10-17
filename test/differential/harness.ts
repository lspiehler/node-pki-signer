// Signs one corpus case with the reference path and a candidate, then compares the results.
import { compareCertificates, opensslVerify, textDifferences, type Difference } from './compare.ts';
import { referenceSigner, type Signer, type SignParams } from './reference.ts';

const ctPoison = '1.3.6.1.4.1.11129.2.4.3';

export type Outcome =
  | { kind: 'both rejected'; reference: string; candidate: string }
  | { kind: 'one rejected'; reference: string; candidate: string; candidatePEM?: string }
  | {
      kind: 'both signed';
      candidatePEM: string;
      differences: Difference[];
      text: string[];
      /** `openssl verify` errors, if any */
      verify: { reference?: string; candidate?: string };
    };

async function attempt(signer: Signer, params: SignParams): Promise<{ pem: string } | { error: string }> {
  try {
    return { pem: await signer(params) };
  } catch (err) {
    return { error: err instanceof Error ? err.message : String(err) };
  }
}

/** `sequential` signs with the reference first, for keys several processes can't use at once. */
export async function differential(params: SignParams, candidate: Signer, sequential = false): Promise<Outcome> {
  const [ref, cand] = sequential
    ? [await attempt(referenceSigner, params), await attempt(candidate, params)]
    : await Promise.all([attempt(referenceSigner, params), attempt(candidate, params)]);
  if ('error' in ref || 'error' in cand) {
    const describe = (r: typeof ref) => ('error' in r ? r.error : 'signed');
    return {
      kind: 'error' in ref && 'error' in cand ? 'both rejected' : 'one rejected',
      reference: describe(ref),
      candidate: describe(cand),
      ...('pem' in cand ? { candidatePEM: cand.pem } : {}),
    };
  }
  const customOIDs = (params.options.extensions?.customOIDs ?? []) as { OID: string }[];
  const precertificate = customOIDs.some((o) => o.OID === ctPoison);
  const [text, verifyRef, verifyCand] = await Promise.all([
    textDifferences(ref.pem, cand.pem),
    opensslVerify(ref.pem, params.ca, precertificate),
    opensslVerify(cand.pem, params.ca, precertificate),
  ]);
  return {
    kind: 'both signed',
    candidatePEM: cand.pem,
    differences: compareCertificates(ref.pem, cand.pem),
    text,
    verify: { reference: verifyRef, candidate: verifyCand },
  };
}
