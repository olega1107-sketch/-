import { afterEach, describe, expect, it } from 'vitest';

import { buildDirectorApp } from '../src/app.js';
import { StaticBearerAuthenticator } from '../src/service-auth.js';
import {
  capabilitySecret,
  createDirectorFixture,
  gatewayBearerToken,
  ids,
  type DirectorFixture,
} from './helpers.js';

describe('Director HTTP contract', () => {
  let fixture: DirectorFixture | undefined;
  let app: ReturnType<typeof buildDirectorApp> | undefined;

  afterEach(async () => {
    await app?.close();
    await fixture?.close();
    app = undefined;
    fixture = undefined;
  });

  it('redeems through the exact colon-suffix route with service authentication', async () => {
    fixture = await createDirectorFixture();
    app = buildDirectorApp({
      service: fixture.service,
      authenticator: new StaticBearerAuthenticator({
        token: gatewayBearerToken,
        requireMutualTls: false,
      }),
    });

    const response = await app.inject({
      method: 'POST',
      url: `/internal/v1/agent-runs/${ids.run}/context-bundle:redeem`,
      headers: {
        authorization: `Bearer ${gatewayBearerToken}`,
        'x-agent-capability': capabilitySecret,
        'x-request-id': ids.callerRequest,
      },
      payload: fixture.redeemRequest,
    });

    expect(response.statusCode, response.body).toBe(200);
    expect(response.headers['x-request-id']).toBe(ids.callerRequest);
    expect(response.json()).toMatchObject({
      agent_run_id: ids.run,
      context_set_hash: fixture.executionRequest.context_set_hash,
      item_count: 1,
    });
  });

  it('rejects an unauthenticated caller before consuming the capability', async () => {
    fixture = await createDirectorFixture();
    app = buildDirectorApp({
      service: fixture.service,
      authenticator: new StaticBearerAuthenticator({
        token: gatewayBearerToken,
        requireMutualTls: false,
      }),
    });

    const response = await app.inject({
      method: 'POST',
      url: `/internal/v1/agent-runs/${ids.run}/context-bundle:redeem`,
      headers: { 'x-agent-capability': capabilitySecret },
      payload: fixture.redeemRequest,
    });

    expect(response.statusCode).toBe(401);
    expect(response.json()).toMatchObject({
      error: { code: 'unauthorized_service', retryable: false },
    });
    const capability = await fixture.database.query<{ usedAt: string | null }>(
      `
        SELECT used_at::text AS "usedAt"
        FROM dirizhor.agent_capabilities
        WHERE id = $1::uuid
      `,
      [ids.capability],
    );
    expect(capability.rows[0]?.usedAt).toBeNull();
  });

  it('reports liveness and dependency readiness without exposing failures', async () => {
    fixture = await createDirectorFixture();
    let ready = true;
    app = buildDirectorApp({
      service: fixture.service,
      authenticator: new StaticBearerAuthenticator({
        token: gatewayBearerToken,
        requireMutualTls: false,
      }),
      readiness: async () => {
        if (!ready) throw new Error('sensitive database host and path');
      },
    });

    const live = await app.inject({ method: 'GET', url: '/health/live' });
    expect(live.statusCode, live.body).toBe(200);
    expect(live.json()).toEqual({ status: 'ok' });
    expect(live.headers['cache-control']).toBe('no-store');

    const available = await app.inject({ method: 'GET', url: '/health/ready' });
    expect(available.statusCode, available.body).toBe(200);
    expect(available.json()).toEqual({ status: 'ok' });

    ready = false;
    const unavailable = await app.inject({ method: 'GET', url: '/health/ready' });
    expect(unavailable.statusCode, unavailable.body).toBe(503);
    expect(unavailable.json()).toEqual({ status: 'unavailable' });
    expect(unavailable.body).not.toContain('sensitive');
  });
});
