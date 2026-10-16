// Runs the system openssl binary (the one node-openssl-cert2 uses) for fixtures and checks.
import { execFile } from 'node:child_process';

export function openssl(args: string[], stdin?: string | Uint8Array): Promise<string> {
  return new Promise((resolve, reject) => {
    const child = execFile(
      'openssl',
      args,
      { encoding: 'utf8', maxBuffer: 16 * 1024 * 1024 },
      (err, stdout, stderr) => {
        if (err) {
          reject(new Error(`openssl ${args[0] ?? ''} failed: ${stderr || err.message}`));
        } else {
          resolve(stdout);
        }
      },
    );
    child.stdin?.end(stdin);
  });
}
