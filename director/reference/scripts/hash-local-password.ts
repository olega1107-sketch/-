import { hashLocalPassword } from '../src/local-password.js';

async function main(): Promise<void> {
  if (process.stdin.isTTY) {
    throw new Error('Read the password from stdin; command-line arguments are not accepted.');
  }
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }
  const password = Buffer.concat(chunks).toString('utf8');
  process.stdout.write(`${await hashLocalPassword(password)}\n`);
}

void main().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : 'Unable to hash the password.';
  process.stderr.write(`${message}\n`);
  process.exitCode = 1;
});
