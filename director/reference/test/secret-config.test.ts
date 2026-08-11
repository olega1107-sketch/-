import { describe, expect, it } from 'vitest';

import { optionalSecret, requiredSecret } from '../src/secret-config.js';

describe('Director mounted secret configuration', () => {
  it('reads a mounted secret and removes one conventional final newline', () => {
    expect(
      requiredSecret(
        { DIRECTOR_GATEWAY_TOKEN_FILE: '/run/secrets/gateway-token' },
        'DIRECTOR_GATEWAY_TOKEN',
        () => 'mounted-secret\n',
      ),
    ).toBe('mounted-secret');
  });

  it('rejects conflicting and multiline secret sources', () => {
    expect(() =>
      optionalSecret(
        {
          DIRECTOR_GATEWAY_TOKEN: 'direct-secret',
          DIRECTOR_GATEWAY_TOKEN_FILE: '/run/secrets/gateway-token',
        },
        'DIRECTOR_GATEWAY_TOKEN',
      ),
    ).toThrow(/must not be set together/);
    expect(() =>
      requiredSecret(
        { DIRECTOR_GATEWAY_TOKEN_FILE: '/run/secrets/gateway-token' },
        'DIRECTOR_GATEWAY_TOKEN',
        () => 'first\nsecond\n',
      ),
    ).toThrow(/single-line secret/);
  });

  it('does not expose the mounted path or filesystem error', () => {
    expect(() =>
      requiredSecret(
        { DATABASE_URL_FILE: '/sensitive/tenant/database-url' },
        'DATABASE_URL',
        () => {
          throw new Error('permission denied for /sensitive/tenant/database-url');
        },
      ),
    ).toThrow('DATABASE_URL_FILE could not be read.');
    try {
      requiredSecret(
        { DATABASE_URL_FILE: '/sensitive/tenant/database-url' },
        'DATABASE_URL',
        () => {
          throw new Error('permission denied');
        },
      );
    } catch (error) {
      expect(String(error)).not.toContain('/sensitive/tenant');
      expect(String(error)).not.toContain('permission denied');
    }
  });
});
