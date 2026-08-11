import { afterEach, describe, expect, it } from 'vitest';

import { buildGatewayApp } from '../src/app.js';
import { FixtureProviderAdapter } from '../src/fixture-provider-adapter.js';
import { GatewayService } from '../src/gateway-service.js';
import type { ServiceAuthenticator } from '../src/ports.js';
import type { AgentExecutionRequest } from '../src/protocol.js';
import { StaticBearerAuthenticator } from '../src/service-auth.js';
import {
  executionFixture,
  FakeDirector,
  ids,
  MemoryExecutionStore,
  SequentialIds,
  TestClock,
} from './helpers.js';

const apps: Array<ReturnType<typeof buildGatewayApp>> = [];
const allowAll: ServiceAuthenticator = { authenticate: () => undefined };

afterEach(async () => {
  await Promise.all(apps.splice(0).map((app) => app.close()));
});

describe('Gateway HTTP contract', () => {
  it('accepts the exact colon-suffix execute and cancel routes', async () => {
    const fixture = executionFixture();
    const service = new GatewayService({
      store: new MemoryExecutionStore(),
      director: new FakeDirector(fixture.bundle),
      adapters: [new FixtureProviderAdapter()],
      clock: new TestClock(),
      idGenerator: new SequentialIds(),
      autoProcess: false,
    });
    let transported:
      | { agentRunId: string; request: AgentExecutionRequest }
      | undefined;
    const executeService = service.execute.bind(service);
    service.execute = async (command) => {
      transported = { agentRunId: command.agentRunId, request: command.request };
      return executeService(command);
    };
    const app = buildGatewayApp({ service, authenticator: allowAll });
    apps.push(app);

    const execute = await app.inject({
      method: 'POST',
      url: `/internal/v1/agent-runs/${fixture.agentRunId}:execute`,
      headers: {
        'idempotency-key': fixture.agentRunId,
        'x-agent-capability': 'capability-secret',
        'x-request-id': ids.callerRequest,
      },
      payload: fixture.request,
    });
    expect(transported).toEqual({
      agentRunId: fixture.agentRunId,
      request: fixture.request,
    });
    expect(execute.statusCode, execute.body).toBe(202);
    expect(execute.headers['x-request-id']).toBe(ids.callerRequest);
    expect(execute.json()).toMatchObject({ gateway_state: 'accepted' });

    const cancel = await app.inject({
      method: 'POST',
      url: `/internal/v1/agent-runs/${fixture.agentRunId}:cancel`,
      headers: { 'idempotency-key': fixture.agentRunId },
      payload: {
        protocol_version: '1.0',
        reason_code: 'user_requested',
        requested_at: '2026-08-10T10:01:00.000Z',
      },
    });
    expect(cancel.statusCode).toBe(202);
    expect(cancel.json()).toMatchObject({ gateway_state: 'accepted' });
  });

  it('returns a protocol error for schema violations without echoing payload', async () => {
    const fixture = executionFixture();
    const service = new GatewayService({
      store: new MemoryExecutionStore(),
      director: new FakeDirector(fixture.bundle),
      adapters: [new FixtureProviderAdapter()],
      autoProcess: false,
    });
    const app = buildGatewayApp({ service, authenticator: allowAll });
    apps.push(app);

    const response = await app.inject({
      method: 'POST',
      url: `/internal/v1/agent-runs/${fixture.agentRunId}:execute`,
      headers: { 'x-agent-capability': 'do-not-echo-this' },
      payload: fixture.request,
    });

    expect(response.statusCode).toBe(400);
    expect(response.json()).toMatchObject({
      error: { code: 'validation_error', retryable: false },
    });
    expect(response.body).not.toContain('do-not-echo-this');
  });

  it('enforces service bearer authentication before execution', async () => {
    const fixture = executionFixture();
    const director = new FakeDirector(fixture.bundle);
    const service = new GatewayService({
      store: new MemoryExecutionStore(),
      director,
      adapters: [new FixtureProviderAdapter()],
      autoProcess: false,
    });
    const app = buildGatewayApp({
      service,
      authenticator: new StaticBearerAuthenticator({
        token: 'director-token',
        requireMutualTls: false,
      }),
    });
    apps.push(app);

    const response = await app.inject({
      method: 'POST',
      url: `/internal/v1/agent-runs/${fixture.agentRunId}:execute`,
      headers: {
        'idempotency-key': fixture.agentRunId,
        'x-agent-capability': 'capability-secret',
      },
      payload: fixture.request,
    });

    expect(response.statusCode).toBe(401);
    expect(response.json()).toMatchObject({ error: { code: 'unauthorized_service' } });
    expect(director.redeemCalls).toHaveLength(0);
  });

  it('reports liveness and state-store readiness without exposing failures', async () => {
    const fixture = executionFixture();
    const service = new GatewayService({
      store: new MemoryExecutionStore(),
      director: new FakeDirector(fixture.bundle),
      adapters: [new FixtureProviderAdapter()],
      autoProcess: false,
    });
    let ready = true;
    const app = buildGatewayApp({
      service,
      authenticator: allowAll,
      readiness: async () => {
        if (!ready) throw new Error('sensitive state directory');
      },
    });
    apps.push(app);

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
