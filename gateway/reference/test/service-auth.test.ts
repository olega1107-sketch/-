import { describe, expect, it } from 'vitest';

import { StaticBearerAuthenticator } from '../src/service-auth.js';

describe('Gateway service authentication configuration', () => {
  it('requires an explicit peer identity when mutual TLS is enabled', () => {
    expect(
      () => new StaticBearerAuthenticator({ token: 'director-service-token' }),
    ).toThrow(/allowed Director certificate Common Name/);
  });
});
