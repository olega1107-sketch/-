import { MockAgent } from 'undici';
import { describe, expect, it } from 'vitest';

import { DirectorClientError } from '../src/errors.js';
import { HttpDirectorClient } from '../src/http-director-client.js';
import type { GatewayEvent } from '../src/protocol.js';
import { executionFixture, ids } from './helpers.js';

describe('HttpDirectorClient', () => {
  it('uses fixed Director paths and sends capability only to context redeem', async () => {
    const fixture = executionFixture();
    const calls: Array<{ url: string; headers: Headers }> = [];
    const fetcher: typeof fetch = async (input, init) => {
      const url = input instanceof Request ? input.url : String(input);
      calls.push({ url, headers: new Headers(init?.headers) });
      if (url.endsWith('/events')) {
        return new Response(null, { status: 204 });
      }
      return Response.json(fixture.bundle);
    };
    const client = new HttpDirectorClient({
      baseUrl: 'http://director.internal/',
      tokenProvider: () => 'short-lived-service-token',
      fetch: fetcher,
      allowHttpForDevelopment: true,
    });

    await expect(
      client.redeemContextBundle(
        fixture.agentRunId,
        'one-time-capability',
        {
          protocol_version: '1.0',
          request_fingerprint: fixture.request.request_fingerprint,
          expected_context_set_hash: fixture.request.context_set_hash,
        },
        ids.callerRequest,
      ),
    ).resolves.toEqual(fixture.bundle);
    await client.recordEvent(fixture.agentRunId, startedEvent(fixture), ids.callerRequest);

    expect(calls.map((call) => call.url)).toEqual([
      `http://director.internal/internal/v1/agent-runs/${fixture.agentRunId}/context-bundle:redeem`,
      `http://director.internal/internal/v1/agent-runs/${fixture.agentRunId}/events`,
    ]);
    expect(calls[0]?.headers.get('authorization')).toBe('Bearer short-lived-service-token');
    expect(calls[0]?.headers.get('x-agent-capability')).toBe('one-time-capability');
    expect(calls[1]?.headers.has('x-agent-capability')).toBe(false);
  });

  it('marks retryable Director event failures without exposing response bodies', async () => {
    const fixture = executionFixture();
    const client = new HttpDirectorClient({
      baseUrl: 'https://director.internal/',
      tokenProvider: () => 'service-token',
      fetch: async () =>
        new Response('sensitive upstream body', {
          status: 503,
          headers: { 'retry-after': '7' },
        }),
    });

    const failure = client.recordEvent(
      fixture.agentRunId,
      startedEvent(fixture),
      ids.callerRequest,
    );

    await expect(failure).rejects.toMatchObject({
      statusCode: 503,
      retryable: true,
      retryAfterSeconds: 7,
    });
    await expect(failure).rejects.not.toThrow('sensitive upstream body');
    await expect(failure).rejects.toBeInstanceOf(DirectorClientError);
  });

  it('uses the configured dispatcher for protected Director transport', async () => {
    const fixture = executionFixture();
    const dispatcher = new MockAgent();
    dispatcher.disableNetConnect();
    dispatcher
      .get('https://director.internal')
      .intercept({
        path: `/internal/v1/agent-runs/${fixture.agentRunId}/context-bundle:redeem`,
        method: 'POST',
      })
      .reply(200, fixture.bundle);
    const client = new HttpDirectorClient({
      baseUrl: 'https://director.internal/',
      tokenProvider: () => 'gateway-service-token',
      dispatcher,
    });

    try {
      await expect(
        client.redeemContextBundle(
          fixture.agentRunId,
          'one-time-capability',
          {
            protocol_version: '1.0',
            request_fingerprint: fixture.request.request_fingerprint,
            expected_context_set_hash: fixture.request.context_set_hash,
          },
          ids.callerRequest,
        ),
      ).resolves.toEqual(fixture.bundle);
      expect(dispatcher.pendingInterceptors()).toHaveLength(0);
    } finally {
      await dispatcher.close();
    }
  });

  it('fails closed without a protected dispatcher and rejects credentialed URLs', () => {
    expect(
      () =>
        new HttpDirectorClient({
          baseUrl: 'https://director.internal/',
          tokenProvider: () => 'token',
        }),
    ).toThrow(/mutual TLS dispatcher/);
    expect(
      () =>
        new HttpDirectorClient({
          baseUrl: 'https://user:secret@director.internal/',
          tokenProvider: () => 'token',
          fetch: async () => new Response(null, { status: 204 }),
        }),
    ).toThrow(/must not contain credentials/);
  });
});

function startedEvent(fixture: ReturnType<typeof executionFixture>): GatewayEvent {
  return {
    protocol_version: '1.0',
    event_id: '20000000-0000-4000-8000-000000000001',
    event_type: 'agent_run.started',
    event_hash: 'sha256:0000000000000000000000000000000000000000000000000000000000000000',
    agent_run_id: fixture.agentRunId,
    project_id: fixture.request.project_id,
    origin_request_id: fixture.request.origin_request_id,
    request_fingerprint: fixture.request.request_fingerprint,
    occurred_at: '2026-08-10T10:00:01.000Z',
    provider: fixture.request.provider,
    model: fixture.request.model ?? null,
    adapter_version: 'fixture/1',
    context_set_hash: fixture.request.context_set_hash,
  };
}
