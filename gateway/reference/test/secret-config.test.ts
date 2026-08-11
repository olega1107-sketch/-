import { describe, expect, it } from 'vitest';

import { optionalSecret, requiredSecret } from '../src/secret-config.js';

describe('Gateway mounted secret configuration', () => {
  it('reads a mounted secret and removes one conventional final newline', () => {
    expect(
      requiredSecret(
        { OPENAI_API_KEY_FILE: '/run/secrets/openai-api-key' },
        'OPENAI_API_KEY',
        () => 'mounted-secret\r\n',
      ),
    ).toBe('mounted-secret');
  });

  it('rejects conflicting and multiline secret sources', () => {
    expect(() =>
      optionalSecret(
        {
          OPENAI_API_KEY: 'direct-secret',
          OPENAI_API_KEY_FILE: '/run/secrets/openai-api-key',
        },
        'OPENAI_API_KEY',
      ),
    ).toThrow(/must not be set together/);
    expect(() =>
      requiredSecret(
        { OPENAI_API_KEY_FILE: '/run/secrets/openai-api-key' },
        'OPENAI_API_KEY',
        () => 'first\nsecond\n',
      ),
    ).toThrow(/single-line secret/);
  });

  it('does not expose the mounted path or filesystem error', () => {
    expect(() =>
      requiredSecret(
        { GATEWAY_SPOOL_KEY_BASE64_FILE: '/sensitive/tenant/spool-key' },
        'GATEWAY_SPOOL_KEY_BASE64',
        () => {
          throw new Error('permission denied for /sensitive/tenant/spool-key');
        },
      ),
    ).toThrow('GATEWAY_SPOOL_KEY_BASE64_FILE could not be read.');
    try {
      requiredSecret(
        { GATEWAY_SPOOL_KEY_BASE64_FILE: '/sensitive/tenant/spool-key' },
        'GATEWAY_SPOOL_KEY_BASE64',
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
