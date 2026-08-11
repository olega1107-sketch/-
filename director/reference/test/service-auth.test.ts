import { describe, expect, it } from 'vitest';

import { StaticBearerAuthenticator } from '../src/service-auth.js';

describe('Director service authentication configuration', () => {
  it('requires an explicit peer identity when mutual TLS is enabled', () => {
    expect(
      () => new StaticBearerAuthenticator({ token: 'gateway-service-token' }),
    ).toThrow(/allowed Gateway certificate Common Name/);
  });
});
