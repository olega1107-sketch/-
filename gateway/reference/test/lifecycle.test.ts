import { describe, expect, it, vi } from 'vitest';

import { computeEventHash, computeRequestFingerprint } from '../src/canonical.js';
import { DirectorClientError } from '../src/errors.js';
import { FixtureProviderAdapter } from '../src/fixture-provider-adapter.js';
import { GatewayService } from '../src/gateway-service.js';
import type { ExecutionRecord } from '../src/ports.js';
import {
  executeCommand,
  executionFixture,
  FakeDirector,
  ids,
  MemoryExecutionStore,
  SequentialIds,
  TestClock,
} from './helpers.js';

function serviceFixture(options?: { adapter?: FixtureProviderAdapter; director?: FakeDirector }) {
  const fixture = executionFixture();
  const store = new MemoryExecutionStore();
  const director = options?.director ?? new FakeDirector(fixture.bundle);
  const adapter = options?.adapter ?? new FixtureProviderAdapter();
  const clock = new TestClock();
  const service = new GatewayService({
    store,
    director,
    adapters: [adapter],
    clock,
    idGenerator: new SequentialIds(),
    autoProcess: false,
  });
  return { fixture, store, director, adapter, clock, service };
}

describe('GatewayService lifecycle', () => {
  it('delivers started before one provider call and then completes', async () => {
    const { fixture, store, director, adapter, service } = serviceFixture();

    await expect(service.execute(executeCommand(fixture))).resolves.toMatchObject({
      gateway_state: 'accepted',
      agent_run_id: fixture.agentRunId,
    });
    expect(director.redeemCalls).toHaveLength(1);
    await service.drain(fixture.agentRunId);

    expect(director.events.map((event) => event.event_type)).toEqual([
      'agent_run.started',
      'agent_run.completed',
    ]);
    expect(adapter.calls).toHaveLength(1);
    for (const event of director.events) {
      const { event_hash: hash, ...body } = event;
      expect(hash).toBe(computeEventHash(body));
    }
    const record = await store.load(fixture.agentRunId);
    expect(record).toMatchObject({
      phase: 'completed',
      terminalEventType: 'agent_run.completed',
      eventIds: expect.arrayContaining([director.events[0]?.event_id, director.events[1]?.event_id]),
    });
    expect(record?.request).toBeUndefined();
    expect(record?.context).toBeUndefined();
    expect(record?.pendingEvent).toBeUndefined();
  });

  it('reports pending execution count and oldest accepted age without exposing records', async () => {
    const { fixture, clock, service } = serviceFixture();
    await service.execute(executeCommand(fixture));
    clock.set('2026-08-10T10:10:00.000Z');

    await expect(service.inspectQueue()).resolves.toEqual({ pending: 1, oldestSeconds: 600 });
  });

  it('does not redeem context or invoke provider again for duplicate execute', async () => {
    const { fixture, director, adapter, clock, service } = serviceFixture();
    await service.execute(executeCommand(fixture));
    await service.drain(fixture.agentRunId);
    clock.set('2026-08-10T12:00:00.000Z');

    await expect(service.execute(executeCommand(fixture))).resolves.toMatchObject({
      gateway_state: 'terminal',
    });
    expect(director.redeemCalls).toHaveLength(1);
    expect(adapter.calls).toHaveLength(1);

    const changed = structuredClone(fixture.request);
    changed.purpose = 'Different purpose';
    changed.request_fingerprint = computeRequestFingerprint(fixture.agentRunId, changed);
    await expect(
      service.execute({ ...executeCommand(fixture), request: changed }),
    ).rejects.toMatchObject({
      statusCode: 409,
      code: 'idempotency_conflict',
    });
  });

  it('rejects corrupt context before acceptance or provider dispatch', async () => {
    const fixture = executionFixture();
    fixture.bundle.items[0]!.content = 'tampered';
    const director = new FakeDirector(fixture.bundle);
    const adapter = new FixtureProviderAdapter();
    const store = new MemoryExecutionStore();
    const service = new GatewayService({
      store,
      director,
      adapters: [adapter],
      clock: new TestClock(),
      autoProcess: false,
    });

    await expect(service.execute(executeCommand(fixture))).rejects.toMatchObject({
      code: 'context_hash_mismatch',
      statusCode: 422,
    });
    expect(await store.load(fixture.agentRunId)).toBeUndefined();
    expect(adapter.calls).toHaveLength(0);
  });

  it('rejects a provider profile on an internal execution before context redemption', async () => {
    const fixture = executionFixture({ providerDataProfileVersion: 'misclassified-profile' });
    const director = new FakeDirector(fixture.bundle);
    const service = new GatewayService({
      store: new MemoryExecutionStore(),
      director,
      adapters: [new FixtureProviderAdapter()],
      clock: new TestClock(),
      autoProcess: false,
    });

    await expect(service.execute(executeCommand(fixture))).rejects.toMatchObject({
      statusCode: 422,
      code: 'policy_violation',
    });
    expect(director.redeemCalls).toHaveLength(0);
  });

  it('retries started delivery with the same event ID and hash', async () => {
    const fixture = executionFixture();
    const director = new FakeDirector(fixture.bundle);
    director.eventHandler = async (event, attempt) => {
      if (event.event_type === 'agent_run.started' && attempt === 1) {
        throw new DirectorClientError('temporary', 503, true);
      }
    };
    const { service, adapter } = serviceFixture({ director });
    await service.execute(executeCommand(fixture));

    await expect(service.drain(fixture.agentRunId)).rejects.toBeInstanceOf(DirectorClientError);
    await service.drain(fixture.agentRunId);

    expect(director.eventAttempts.slice(0, 2).map((event) => [event.event_id, event.event_hash])).toEqual([
      [director.eventAttempts[0]?.event_id, director.eventAttempts[0]?.event_hash],
      [director.eventAttempts[0]?.event_id, director.eventAttempts[0]?.event_hash],
    ]);
    expect(adapter.calls).toHaveLength(1);
  });

  it('cancels an active provider call and ignores its late outcome', async () => {
    const adapter = new FixtureProviderAdapter(
      async (_invocation, signal) =>
        new Promise((resolve) => {
          signal.addEventListener(
            'abort',
            () =>
              resolve({
                content: 'late result',
                contentType: 'text/plain',
                finishReason: 'stop',
                providerRequestId: 'late-provider-id',
              }),
            { once: true },
          );
        }),
    );
    const { fixture, director, store, service } = serviceFixture({ adapter });
    await service.execute(executeCommand(fixture));
    const processing = service.drain(fixture.agentRunId);
    await vi.waitFor(() => expect(adapter.calls).toHaveLength(1));

    await service.cancel({
      agentRunId: fixture.agentRunId,
      idempotencyKey: fixture.agentRunId,
      requestId: ids.callerRequest,
      request: {
        protocol_version: '1.0',
        reason_code: 'user_requested',
        reason: 'Stop',
        requested_at: '2026-08-10T10:01:00.000Z',
      },
    });
    await processing;

    expect(director.events.map((event) => event.event_type)).toEqual([
      'agent_run.started',
      'agent_run.cancelled',
    ]);
    expect(await store.load(fixture.agentRunId)).toMatchObject({ phase: 'cancelled' });
  });

  it('fails safely instead of replaying a provider call after recovery', async () => {
    const fixture = executionFixture();
    const store = new MemoryExecutionStore();
    const record: ExecutionRecord = {
      version: 1,
      agentRunId: fixture.agentRunId,
      requestFingerprint: fixture.request.request_fingerprint,
      acceptedAt: '2026-08-10T10:00:00.000Z',
      phase: 'provider_calling',
      eventIds: ['20000000-0000-4000-8000-000000000099'],
      request: fixture.request,
      context: fixture.bundle,
      startedAt: '2026-08-10T10:00:01.000Z',
    };
    await store.save(record);
    const director = new FakeDirector(fixture.bundle);
    const adapter = new FixtureProviderAdapter();
    const service = new GatewayService({
      store,
      director,
      adapters: [adapter],
      clock: new TestClock(),
      idGenerator: new SequentialIds(),
      autoProcess: false,
    });

    await service.resumePending();

    expect(adapter.calls).toHaveLength(0);
    expect(director.events).toHaveLength(1);
    expect(director.events[0]).toMatchObject({
      event_type: 'agent_run.failed',
      failure: { code: 'provider_outcome_unknown', retryable: false },
    });
    expect(await store.load(fixture.agentRunId)).toMatchObject({ phase: 'failed' });
  });
});
