import { describe, expect, it } from 'vitest';

import { InternalInferenceAdapter } from '../src/internal-inference-adapter.js';
import type { ProviderInvocation } from '../src/ports.js';
import { executionFixture } from './helpers.js';

describe('InternalInferenceAdapter', () => {
  it('sends a fixed authenticated request and accepts only the matching response', async () => {
    const fixture = internalFixture();
    const calls: Array<{ url: string; init: RequestInit }> = [];
    const adapter = new InternalInferenceAdapter({
      origin: 'http://inference.internal.test',
      models: ['internal-model-v1'],
      tokenProvider: () => 'internal-service-token',
      allowHttpForDevelopment: true,
      fetch: async (input, init) => {
        calls.push({ url: String(input), init: init ?? {} });
        return Response.json(responseFixture(fixture));
      },
    });

    expect(adapter.supports(fixture.request)).toBe(true);
    const result = await adapter.execute(
      invocation(fixture),
      new AbortController().signal,
    );

    expect(result).toEqual({
      content: 'Internal result',
      contentType: 'text/markdown',
      finishReason: 'stop',
      providerRequestId: 'internal:req-123',
      usage: { input_tokens: 7, output_tokens: 2 },
      outputSummary: null,
    });
    expect(calls).toHaveLength(1);
    expect(calls[0]?.url).toBe('http://inference.internal.test/v1/generate');
    const headers = new Headers(calls[0]?.init.headers);
    expect(headers.get('authorization')).toBe('Bearer internal-service-token');
    expect(headers.get('idempotency-key')).toBe(fixture.agentRunId);
    expect(headers.get('x-request-id')).toBe(fixture.request.origin_request_id);
    const body = JSON.parse(String(calls[0]?.init.body)) as Record<string, unknown>;
    expect(body).toMatchObject({
      protocol_version: '1.0',
      agent_run_id: fixture.agentRunId,
      model: 'internal-model-v1',
      context: {
        context_set_hash: fixture.bundle.context_set_hash,
        items: [
          expect.objectContaining({
            content: fixture.bundle.items[0]?.content,
            content_hash: fixture.bundle.items[0]?.content_hash,
          }),
        ],
      },
    });
    expect(JSON.stringify(body)).not.toContain('capability-secret');
    expect(JSON.stringify(body)).not.toContain('internal-service-token');
  });

  it('rejects external, profiled, and unapproved-model requests', () => {
    const adapter = adapterFixture();
    const external = internalFixture();
    external.request.deployment_class = 'external';
    external.request.provider_data_profile_version = 'profile-v1';
    expect(adapter.supports(external.request)).toBe(false);

    const profiled = internalFixture();
    profiled.request.provider_data_profile_version = 'profile-v1';
    expect(adapter.supports(profiled.request)).toBe(false);

    const unknownModel = internalFixture();
    unknownModel.request.model = 'unknown-model';
    expect(adapter.supports(unknownModel.request)).toBe(false);
  });

  it('fails closed on identity drift, oversized JSON, and upstream errors without body leakage', async () => {
    const fixture = internalFixture();
    const mismatched = new InternalInferenceAdapter({
      origin: 'http://inference.internal.test',
      models: ['internal-model-v1'],
      tokenProvider: () => 'token',
      allowHttpForDevelopment: true,
      fetch: async () =>
        Response.json({
          ...responseFixture(fixture),
          agent_run_id: '20000000-0000-4000-8000-000000000099',
        }),
    });
    await expect(
      mismatched.execute(invocation(fixture), new AbortController().signal),
    ).rejects.toMatchObject({ code: 'normalization_failed' });

    const oversized = new InternalInferenceAdapter({
      origin: 'http://inference.internal.test',
      models: ['internal-model-v1'],
      tokenProvider: () => 'token',
      allowHttpForDevelopment: true,
      maxResponseBytes: 32,
      fetch: async () => Response.json(responseFixture(fixture)),
    });
    await expect(
      oversized.execute(invocation(fixture), new AbortController().signal),
    ).rejects.toMatchObject({ code: 'output_too_large' });

    const unavailable = new InternalInferenceAdapter({
      origin: 'http://inference.internal.test',
      models: ['internal-model-v1'],
      tokenProvider: () => 'token',
      allowHttpForDevelopment: true,
      fetch: async () =>
        new Response('sensitive internal provider details', {
          status: 503,
          headers: {
            'retry-after': '4',
            'x-provider-request-id': 'internal:req-failed',
          },
        }),
    });
    const failure = unavailable.execute(
      invocation(fixture),
      new AbortController().signal,
    );
    await expect(failure).rejects.toMatchObject({
      code: 'provider_unavailable',
      retryable: true,
      providerStatus: 503,
      retryAfterSeconds: 4,
      providerRequestId: 'internal:req-failed',
    });
    await expect(failure).rejects.not.toThrow('sensitive internal provider details');
  });

  it('requires an exact DNS origin and protected HTTPS dispatcher', () => {
    expect(
      () =>
        new InternalInferenceAdapter({
          origin: 'https://inference.internal.test',
          models: ['internal-model-v1'],
          tokenProvider: () => 'token',
        }),
    ).toThrow(/mutual TLS dispatcher/);
    expect(
      () =>
        new InternalInferenceAdapter({
          origin: 'https://127.0.0.1',
          models: ['internal-model-v1'],
          tokenProvider: () => 'token',
          fetch: async () => Response.json({}),
        }),
    ).toThrow(/exact HTTPS DNS origin/);
    expect(
      () =>
        new InternalInferenceAdapter({
          origin: 'https://inference.internal.test/base',
          models: ['internal-model-v1'],
          tokenProvider: () => 'token',
          fetch: async () => Response.json({}),
        }),
    ).toThrow(/exact HTTPS DNS origin/);
  });
});

function adapterFixture() {
  return new InternalInferenceAdapter({
    origin: 'http://inference.internal.test',
    models: ['internal-model-v1'],
    tokenProvider: () => 'token',
    allowHttpForDevelopment: true,
    fetch: async () => Response.json({}),
  });
}

function internalFixture() {
  return executionFixture({
    provider: 'internal',
    model: 'internal-model-v1',
    deploymentClass: 'internal',
    providerDataProfileVersion: null,
  });
}

function invocation(fixture: ReturnType<typeof executionFixture>): ProviderInvocation {
  return {
    agentRunId: fixture.agentRunId,
    projectId: fixture.request.project_id,
    originRequestId: fixture.request.origin_request_id,
    agentType: fixture.request.agent_type,
    provider: fixture.request.provider,
    model: fixture.request.model ?? null,
    purpose: fixture.request.purpose,
    instructions: fixture.request.instructions,
    providerDataProfileVersion: fixture.request.provider_data_profile_version ?? null,
    context: fixture.bundle,
    deadlineAt: fixture.request.deadline_at,
  };
}

function responseFixture(fixture: ReturnType<typeof executionFixture>) {
  return {
    protocol_version: '1.0',
    agent_run_id: fixture.agentRunId,
    model: fixture.request.model,
    provider_request_id: 'internal:req-123',
    content: 'Internal result',
    content_type: 'text/markdown',
    finish_reason: 'stop',
    usage: { input_tokens: 7, output_tokens: 2 },
    output_summary: null,
  };
}
