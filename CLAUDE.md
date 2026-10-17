# CLAUDE.md

A library that signs X.509 certificates (and later CRLs, CSRs, OCSP and CMS) in-process for the PKIaaS.io platform (`lspiehler/pkiaas`) and the IoT HSM agent (`lspiehler/iot-hsm`). It replaces one `openssl` process per signature. Decisions and their reasons are in `docs/adr/`; read them before changing the design.

## Changes
- Modify as little code as possible. Follow the existing patterns and coding style.
- Make every change on a branch and open a pull request against `master`. Don't push to `master`; the user merges.
- If you notice anything urgent while working (security, crashes, data loss), report it, even if it's outside the task.
- The repo is public and the package is published to npm (decided 2026-10-17). Prepare version bumps and check the tarball (`npm pack --dry-run`); the user runs `npm publish`.

## Code
- TypeScript, erasable syntax only (tests run with Node's type stripping); `async`/`await`. The package is published as compiled ES modules plus types (`npm run build` → `dist/`), because Node won't strip types inside `node_modules`. CommonJS callers load it with `require()`.
- Prefer what Node and well-maintained libraries provide (`node:crypto`, `@peculiar/asn1-*`, `@google-cloud/kms`, `pkcs11js`) over custom code, unless they're incompatible, need heavy customization, are vulnerable, or bloat dependencies.
- Every key custody is a `SigningKey` backend (`src/signing-key.ts`). Building structures never depends on where the key lives.
- Algorithm agility (ADR 0001): an algorithm × backend runs natively only when it is on the allowlist, and only after the differential tests against OpenSSL pass for it. Everything else falls back to OpenSSL: the OpenSSL backend signs our to-be-signed bytes, or the whole operation goes to node-openssl-cert2. Log every fallback with its reason. A per-algorithm setting can force OpenSSL.
- Output must match today's OpenSSL output (see ADR 0001: forced subject and string types, SKI/AKI, random serial, CSR extensions never copied, `customOIDs` syntax). Any intended difference needs an ADR.
- Stateless: no files, no caches of keys. The only state allowed is long-lived clients and sessions (the Google KMS client, PKCS#11 sessions).

## Secrets
- Never log or put in errors: private keys, passphrases, PINs, KMS credentials, CSRs (they can contain the SCEP challenge).
- Keys stay in memory (`KeyObject`), never in temp files. When the OpenSSL fallback needs a key, pass it on stdin, not in a file or argument.

## Errors
- Every failure says which step failed (e.g. "build TBS", "KMS asymmetricSign", "verify signature") so callers can log a meaningful message to the CA's log.

## Tests
- `node:test`. Check every signing path against OpenSSL 3.5 (`openssl verify`, `openssl x509 -text`) and, for migrated functions, byte-for-byte against node-openssl-cert2's output with the serial and dates fixed (the differential harness in `test/differential/`, see `docs/differential-harness.md`). Add a corpus case for every input shape a caller can send.
- Before committing, run `npm run typecheck`, `npm run lint`, `npm run format:check` and `npm test`.
- CI runs on GitHub-hosted runners in an Ubuntu 26.04 container. Never move it to the user's self-hosted runners: once the repo is public, pull requests from forks would run on them.

## Dependencies
- Exact versions published at least 14 days earlier (`npm install --before=<date>`). The user's own packages (published from lspiehler repos, e.g. node-openssl-cert2) are exempt. TypeScript stays on 5.9.x, matching pkiaas.
