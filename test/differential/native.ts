// The candidate: the library's native signer.
import { caSignCSR } from '../../src/index.ts';
import type { Signer } from './reference.ts';

export const nativeSigner: Signer = async (params) => (await caSignCSR(params)).data;
