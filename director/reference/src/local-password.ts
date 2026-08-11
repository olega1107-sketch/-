import { randomBytes, scrypt, timingSafeEqual } from 'node:crypto';

const saltBytes = 16;
const derivedKeyBytes = 32;
const scryptN = 32_768;
const scryptR = 8;
const scryptP = 1;
const scryptMaxMemory = 64 * 1024 * 1024;
const encodedHashPattern =
  /^\$scrypt\$v=1\$ln=15,r=8,p=1\$([A-Za-z0-9_-]{22})\$([A-Za-z0-9_-]{43})$/;

export const dummyLocalPasswordHash =
  '$scrypt$v=1$ln=15,r=8,p=1$WlpaWlpaWlpaWlpaWlpaWg$u2RfbzJZD6nwR5fWJCKTdyhXgYQ_wl9Ntg9XzhJNxAk';

export async function hashLocalPassword(
  password: string,
  salt: Uint8Array = randomBytes(saltBytes),
): Promise<string> {
  validateLocalPassword(password);
  if (salt.byteLength !== saltBytes) {
    throw new Error(`Local password salt must contain exactly ${saltBytes} bytes.`);
  }
  const encodedSalt = Buffer.from(salt).toString('base64url');
  const derived = await derive(password, Buffer.from(salt));
  return `$scrypt$v=1$ln=15,r=8,p=1$${encodedSalt}$${derived.toString('base64url')}`;
}

export async function verifyLocalPassword(password: string, encodedHash: string): Promise<boolean> {
  const match = encodedHashPattern.exec(encodedHash);
  if (match?.[1] === undefined || match[2] === undefined) {
    return false;
  }
  const salt = Buffer.from(match[1], 'base64url');
  const expected = Buffer.from(match[2], 'base64url');
  if (salt.byteLength !== saltBytes || expected.byteLength !== derivedKeyBytes) {
    return false;
  }
  const received = await derive(password, salt);
  return timingSafeEqual(received, expected);
}

export function validateLocalPassword(password: string): void {
  const bytes = Buffer.byteLength(password, 'utf8');
  if (bytes < 1 || bytes > 1024) {
    throw new Error('Local password must contain between 1 and 1024 UTF-8 bytes.');
  }
}

function derive(password: string, salt: Buffer): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    scrypt(
      password,
      salt,
      derivedKeyBytes,
      { N: scryptN, r: scryptR, p: scryptP, maxmem: scryptMaxMemory },
      (error, result) => {
        if (error !== null) {
          reject(error);
          return;
        }
        resolve(result);
      },
    );
  });
}
