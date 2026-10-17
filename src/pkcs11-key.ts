// Keys on a PKCS#11 token (YubiKey, SoftHSM), signing with pkcs11js (ADR 0003). Each module stays
// loaded and each token keeps one logged-in session between signatures; every signature opens its
// own session, which shares that login, and looks the key up again.
import { createHash, timingSafeEqual } from 'node:crypto';
import * as asn1js from 'asn1js';
import type * as Pkcs11js from 'pkcs11js';
import { signatureHash } from './algorithms.ts';
import { SignerError, UnsupportedError } from './errors.ts';
import type { Pkcs11KeyRef } from './options.ts';
import type { SigningKey } from './signing-key.ts';

type Pkcs11Module = typeof Pkcs11js;

// what RSASSA-PKCS1-v1_5 puts before the digest (RFC 8017 section 9.2)
const digestInfo: Record<string, string> = {
  sha1: '3021300906052b0e03021a05000414',
  sha224: '302d300d06096086480165030402040500041c',
  sha256: '3031300d060960864801650304020105000420',
  sha384: '3041300d060960864801650304020205000430',
  sha512: '3051300d060960864801650304020305000440',
};

/** The attributes of an RFC 7512 PKCS#11 URI's path, percent-decoded. */
export function parsePkcs11URI(uri: string): Map<string, Buffer> {
  if (!uri.startsWith('pkcs11:')) throw new SignerError('parse PKCS#11 URI', 'not a pkcs11: URI');
  const attributes = new Map<string, Buffer>();
  for (const part of (uri.slice('pkcs11:'.length).split('?')[0] ?? '').split(';')) {
    if (!part) continue;
    const separator = part.indexOf('=');
    if (separator < 1) throw new SignerError('parse PKCS#11 URI', 'an attribute has no value');
    const bytes: number[] = [];
    const value = part.slice(separator + 1);
    for (let i = 0; i < value.length; i++) {
      if (value[i] === '%' && /^[0-9a-f]{2}$/i.test(value.slice(i + 1, i + 3))) {
        bytes.push(parseInt(value.slice(i + 1, i + 3), 16));
        i += 2;
      } else {
        bytes.push(...Buffer.from(value[i] ?? ''));
      }
    }
    attributes.set(part.slice(0, separator), Buffer.from(bytes));
  }
  return attributes;
}

// a PKCS#11 error's CKR_ name, without the native stack
const ckr = (err: unknown) => /CKR_[A-Z_]+/.exec(err instanceof Error ? err.message : String(err))?.[0] ?? 'error';

interface Token {
  session: Buffer;
  /** SHA-256 of the PIN it logged in with */
  pin: Buffer;
}

interface LoadedModule {
  pkcs11: Pkcs11js.PKCS11;
  /** by slot handle, hex */
  tokens: Map<string, Token>;
}

/** The loaded PKCS#11 modules and logged-in tokens; one per process, closed on exit. */
export class Pkcs11Sessions {
  #lib: Pkcs11Module | undefined;
  #modules = new Map<string, LoadedModule>();

  async #module(path: string): Promise<{ lib: Pkcs11Module; module: LoadedModule }> {
    if (!this.#lib) {
      try {
        this.#lib = ((await import('pkcs11js')) as { default: Pkcs11Module }).default;
      } catch {
        throw new UnsupportedError('load PKCS#11 module', 'pkcs11js is not installed');
      }
    }
    const lib = this.#lib;
    let module = this.#modules.get(path);
    if (!module) {
      const pkcs11 = new lib.PKCS11();
      try {
        pkcs11.load(path);
        pkcs11.C_Initialize({ flags: lib.CKF_OS_LOCKING_OK });
      } catch (err) {
        // pkcs11js can't use it; openssl may
        throw new UnsupportedError('load PKCS#11 module', `${path}: ${ckr(err)}`);
      }
      module = { pkcs11, tokens: new Map() };
      this.#modules.set(path, module);
    }
    return { lib, module };
  }

  // the slot whose token matches the URI's token attributes
  #slot(pkcs11: Pkcs11js.PKCS11, uri: Map<string, Buffer>): Buffer {
    const wanted: [string, 'serialNumber' | 'label' | 'manufacturerID' | 'model'][] = [
      ['serial', 'serialNumber'],
      ['token', 'label'],
      ['manufacturer', 'manufacturerID'],
      ['model', 'model'],
    ];
    const slots = pkcs11.C_GetSlotList(true).filter((slot) => {
      const info = pkcs11.C_GetTokenInfo(slot);
      return wanted.every(([attribute, field]) => {
        const value = uri.get(attribute);
        return !value || info[field].trim() === value.toString('utf8');
      });
    });
    if (slots.length !== 1) {
      throw new SignerError('find PKCS#11 token', slots.length ? 'more than one token matches' : 'no token matches');
    }
    return slots[0] as Buffer;
  }

  // logs in once per token, again only when the PIN changes
  #login(lib: Pkcs11Module, module: LoadedModule, slot: Buffer, pin: string | undefined): void {
    const id = slot.toString('hex');
    const hash = createHash('sha256')
      .update(pin ?? '')
      .digest();
    const token = module.tokens.get(id);
    if (token && timingSafeEqual(token.pin, hash)) return;
    if (token) this.#logout(module, id);
    const { pkcs11 } = module;
    let session: Buffer;
    try {
      session = pkcs11.C_OpenSession(slot, lib.CKF_SERIAL_SESSION);
    } catch (err) {
      throw new SignerError('open PKCS#11 session', ckr(err));
    }
    if (pin !== undefined) {
      try {
        pkcs11.C_Login(session, lib.CKU_USER, pin);
      } catch (err) {
        if (ckr(err) !== 'CKR_USER_ALREADY_LOGGED_IN') {
          pkcs11.C_CloseSession(session);
          throw new SignerError('PKCS#11 login', ckr(err));
        }
      }
    }
    module.tokens.set(id, { session, pin: hash });
  }

  #logout(module: LoadedModule, id: string): void {
    const token = module.tokens.get(id);
    module.tokens.delete(id);
    if (!token) return;
    try {
      module.pkcs11.C_Logout(token.session);
    } catch {
      // not logged in, or the token is gone
    }
    try {
      module.pkcs11.C_CloseSession(token.session);
    } catch {
      // the token is gone
    }
  }

  /** A SigningKey for an RSA or EC key on a token, signing `algorithm` (the CA certificate's). */
  async key(ref: Pkcs11KeyRef, algorithm: string, publicKey: Uint8Array): Promise<SigningKey> {
    const uri = parsePkcs11URI(ref.uri);
    const hash = signatureHash(algorithm);
    const rsa = algorithm.endsWith('WithRSAEncryption');
    if (!hash || !(rsa || algorithm.startsWith('ecdsa-with-'))) {
      throw new UnsupportedError('load CA key', `${algorithm} with PKCS#11 keys`);
    }
    const prefix = rsa ? digestInfo[hash] : '';
    if (prefix === undefined) throw new UnsupportedError('load CA key', `hash ${hash}`);
    const { lib, module } = await this.#module(ref.modulePath);
    // after a failure (e.g. the token was unplugged), the next signature logs in again
    const reset = () => {
      this.#logout(module, slot.toString('hex'));
    };
    const { pkcs11 } = module;
    const slot = this.#slot(pkcs11, uri);
    const login = () => {
      this.#login(lib, module, slot, ref.pin);
    };
    login();
    const template: Pkcs11js.Template = [{ type: lib.CKA_CLASS, value: lib.CKO_PRIVATE_KEY }];
    const label = uri.get('object');
    const id = uri.get('id');
    if (label) template.push({ type: lib.CKA_LABEL, value: label.toString('utf8') });
    if (id) template.push({ type: lib.CKA_ID, value: id });

    const signOnce = async (input: Buffer): Promise<Uint8Array> => {
      let session: Buffer;
      try {
        session = pkcs11.C_OpenSession(slot, lib.CKF_SERIAL_SESSION);
      } catch (err) {
        reset();
        throw new SignerError('open PKCS#11 session', ckr(err));
      }
      try {
        pkcs11.C_FindObjectsInit(session, template);
        const keys = pkcs11.C_FindObjects(session, 2);
        pkcs11.C_FindObjectsFinal(session);
        if (keys.length !== 1) {
          throw new SignerError(
            'find PKCS#11 key',
            keys.length ? 'more than one private key matches' : 'no private key matches',
          );
        }
        try {
          pkcs11.C_SignInit(session, { mechanism: rsa ? lib.CKM_RSA_PKCS : lib.CKM_ECDSA }, keys[0] as Buffer);
        } catch (err) {
          // the token can't sign this way, so OpenSSL may
          throw new UnsupportedError('PKCS#11 sign', ckr(err));
        }
        const signature = await new Promise<Buffer>((resolve, reject) => {
          pkcs11.C_Sign(session, input, Buffer.alloc(2048), (err: Error | null, data: Buffer) => {
            if (err) reject(new SignerError('PKCS#11 sign', ckr(err)));
            else resolve(data);
          });
        });
        return rsa ? new Uint8Array(signature) : ecdsaDER(signature);
      } catch (err) {
        reset();
        if (err instanceof SignerError) throw err;
        throw new SignerError('find PKCS#11 key', ckr(err));
      } finally {
        try {
          pkcs11.C_CloseSession(session);
        } catch {
          // the token is gone
        }
      }
    };

    return {
      backend: 'pkcs11',
      algorithm,
      publicKey: () => Promise.resolve(publicKey),
      async sign(tbs) {
        const digest = createHash(hash).update(tbs).digest();
        const input = rsa ? Buffer.concat([Buffer.from(prefix, 'hex'), digest]) : digest;
        try {
          return await signOnce(input);
        } catch (err) {
          // another process using a YubiKey resets its login, which hides the private keys from this
          // one until it logs in again (ADR 0003)
          const loggedOut = ['find PKCS#11 key: no private key matches', 'PKCS#11 sign: CKR_USER_NOT_LOGGED_IN'];
          if (!(err instanceof SignerError && loggedOut.includes(err.message))) throw err;
          login();
          return signOnce(input);
        }
      },
    };
  }

  /** Logs out of every token and unloads the modules, e.g. before the agent changes a YubiKey. */
  close(): void {
    for (const module of this.#modules.values()) {
      for (const id of [...module.tokens.keys()]) this.#logout(module, id);
      try {
        module.pkcs11.C_Finalize();
      } catch {
        // already finalized
      }
      module.pkcs11.close();
    }
    this.#modules.clear();
  }
}

/** A PKCS#11 ECDSA signature (r and s, each the size of the curve) as the DER ECDSA-Sig-Value X.509 needs. */
function ecdsaDER(raw: Buffer): Uint8Array {
  const half = raw.length / 2;
  const integer = (bytes: Buffer) => asn1js.Integer.fromBigInt(BigInt(`0x${bytes.toString('hex') || '0'}`));
  const sequence = new asn1js.Sequence({ value: [integer(raw.subarray(0, half)), integer(raw.subarray(half))] });
  return new Uint8Array(sequence.toBER());
}
