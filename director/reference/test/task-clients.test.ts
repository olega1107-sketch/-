import { MockAgent } from 'undici';
import { describe, expect, it } from 'vitest';

import { HmacCapabilityTokenIssuer } from '../src/capability-token.js';
import { HttpAgentGatewayClient } from '../src/http-agent-gateway-client.js';
import type { AgentExecutionRequest } from '../src/protocol.js';
import { ids, times } from './helpers.js';

const fingerprint = `sha256:${'1'.repeat(64)}`;
const contextSetHash = `sha256:${'2'.repeat(64)}`;

describe('Task dispatch adapters', () => {
  it('issues deterministic opaque capability tokens from a canonical key', () => {
    const encodedKey = Buffer.alloc(32, 0x42).toString('base64');
    const issuer = new HmacCapabilityTokenIssuer(
      HmacCapabilityTokenIssuer.keyFromBase64(encodedKey),
    );

    expect(issuer.issue(ids.capability)).toMatch(/^cap_v1\.[A-Za-z0-9_-]{43}$/);
    expect(issuer.issue(ids.capability)).toBe(issuer.issue(ids.capability));
    expect(issuer.issue(ids.run)).not.toBe(issuer.issue(ids.capability));
    expect(() => HmacCapabilityTokenIssuer.keyFromBase64(encodedKey.replace(/=$/, ''))).toThrow(
      /canonical base64/,
    );
  });

  it('sends the exact frozen request and validates the Gateway receipt', async () => {
    let captured: Request | undefined;
    const fetcher: typeof fetch = async (input, init) => {
      captured = new Request(input, init);
      return Response.json(
        {
          protocol_version: '1.0',
          agent_run_id: ids.run,
          request_fingerprint: fingerprint,
          gateway_state: 'accepted',
          accepted_at: times.now,
        },
        { status: 202 },
      );
    };
    const client = new HttpAgentGatewayClient({
      baseUrl: 'http://gateway.internal/base/',
      tokenProvider: () => 'director-service-token',
      fetch: fetcher,
      allowHttpForDevelopment: true,
    });

    await client.dispatch({
      agentRunId: ids.run,
      requestId: ids.callerRequest,
      capability: 'cap_v1.test',
      request: executionRequest(),
    });

    expect(captured?.url).toBe(
      `http://gateway.internal/base/internal/v1/agent-runs/${ids.run}:execute`,
    );
    expect(captured?.method).toBe('POST');
    expect(captured?.headers.get('authorization')).toBe('Bearer director-service-token');
    expect(captured?.headers.get('idempotency-key')).toBe(ids.run);
    expect(captured?.headers.get('x-agent-capability')).toBe('cap_v1.test');
    expect(captured?.headers.get('x-request-id')).toBe(ids.callerRequest);
    await expect(captured?.clone().json()).resolves.toEqual(executionRequest());
  });

  it('preserves Gateway rate-limit retry metadata', async () => {
    const client = new HttpAgentGatewayClient({
      baseUrl: 'http://gateway.internal/',
      tokenProvider: () => 'director-service-token',
      fetch: async () => new Response(null, { status: 429, headers: { 'retry-after': '7' } }),
      allowHttpForDevelopment: true,
    });

    await expect(
      client.dispatch({
        agentRunId: ids.run,
        requestId: ids.callerRequest,
        capability: 'cap_v1.test',
        request: executionRequest(),
      }),
    ).rejects.toMatchObject({
      statusCode: 429,
      code: 'rate_limited',
      retryable: true,
      details: { retry_after_seconds: 7 },
    });
  });

  it('uses the configured dispatcher for protected Gateway transport', async () => {
    const dispatcher = new MockAgent();
    dispatcher.disableNetConnect();
    dispatcher
      .get('https://gateway.internal')
      .intercept({
        path: `/internal/v1/agent-runs/${ids.run}:execute`,
        method: 'POST',
      })
      .reply(202, {
        protocol_version: '1.0',
        agent_run_id: ids.run,
        request_fingerprint: fingerprint,
        gateway_state: 'accepted',
        accepted_at: times.now,
      });
    const client = new HttpAgentGatewayClient({
      baseUrl: 'https://gateway.internal/',
      tokenProvider: () => 'director-service-token',
      dispatcher,
    });

    try {
      await client.dispatch({
        agentRunId: ids.run,
        requestId: ids.callerRequest,
        capability: 'cap_v1.test',
        request: executionRequest(),
      });
      expect(dispatcher.pendingInterceptors()).toHaveLength(0);
    } finally {
      await dispatcher.close();
    }
  });

  it('fails closed without a protected dispatcher and rejects credentialed URLs', () => {
    expect(
      () =>
        new HttpAgentGatewayClient({
          baseUrl: 'https://gateway.internal/',
          tokenProvider: () => 'token',
        }),
    ).toThrow(/mutual TLS dispatcher/);
    expect(
      () =>
        new HttpAgentGatewayClient({
          baseUrl: 'https://user:secret@gateway.internal/',
          tokenProvider: () => 'token',
          fetch: async () => new Response(null, { status: 202 }),
        }),
    ).toThrow(/must not contain credentials/);
  });
});

function executionRequest(): AgentExecutionRequest {
  return {
    protocol_version: '1.0',
    project_id: ids.project,
    task_id: ids.task,
    origin_request_id: ids.originRequest,
    request_fingerprint: fingerprint,
    agent_type: 'architect',
    provider: 'fixture',
    model: null,
    purpose: 'Review the architecture',
    instructions: 'Return only the final recommendation.',
    deployment_class: 'internal',
    provider_data_profile_version: null,
    context_set_hash: contextSetHash,
    context_item_count: 1,
    max_context_sensitivity: 'internal',
    dispatched_at: times.dispatched,
    deadline_at: times.deadline,
  };
}
