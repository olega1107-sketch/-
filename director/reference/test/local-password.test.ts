import { describe, expect, it } from 'vitest';

import {
  dummyLocalPasswordHash,
  hashLocalPassword,
  verifyLocalPassword,
} from '../src/local-password.js';

describe('local password hashing', () => {
  it('encodes a versioned fixed-cost scrypt hash and verifies it safely', async () => {
    const encoded = await hashLocalPassword(
      'correct horse battery staple',
      Buffer.alloc(16, 0x21),
    );

    expect(encoded).toMatch(
      /^\$scrypt\$v=1\$ln=15,r=8,p=1\$[A-Za-z0-9_-]{22}\$[A-Za-z0-9_-]{43}$/,
    );
    await expect(verifyLocalPassword('correct horse battery staple', encoded)).resolves.toBe(true);
    await expect(verifyLocalPassword('wrong password', encoded)).resolves.toBe(false);
    await expect(verifyLocalPassword('password', 'malformed')).resolves.toBe(false);
  });

  it('keeps the dummy credential valid for unknown-login work equalization', async () => {
    await expect(
      verifyLocalPassword('director-dummy-password', dummyLocalPasswordHash),
    ).resolves.toBe(true);
  });

  it('rejects empty and oversized password material before scrypt', async () => {
    await expect(hashLocalPassword('')).rejects.toThrow(/between 1 and 1024/);
    await expect(hashLocalPassword('x'.repeat(1025))).rejects.toThrow(/between 1 and 1024/);
  });
});
