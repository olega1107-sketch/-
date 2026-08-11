import { afterEach, describe, expect, it } from 'vitest';

import { DirectorProtocolError } from '../src/errors.js';
import type { DirectorFixture } from './helpers.js';
import {
  capabilitySecret,
  completedEvent,
  createDirectorFixture,
  ids,
  resealEvent,
  startedEvent,
} from './helpers.js';

describe('DirectorService with PostgreSQL schema v1', () => {
  let fixture: DirectorFixture | undefined;

  afterEach(async () => {
    await fixture?.close();
    fixture = undefined;
  });

  it('redeems a context capability exactly once', async () => {
    fixture = await createDirectorFixture();

    const bundle = await fixture.service.redeemContextBundle(
      ids.run,
      capabilitySecret,
      fixture.redeemRequest,
      ids.callerRequest,
    );

    expect(bundle.items).toHaveLength(1);
    expect(bundle.items[0]?.content).toBe(fixture.contextContent);
    expect(bundle.context_set_hash).toBe(fixture.executionRequest.context_set_hash);
    const capability = await fixture.database.query<{ usedAt: string | null }>(
      `
        SELECT used_at::text AS "usedAt"
        FROM dirizhor.agent_capabilities
        WHERE id = $1::uuid
      `,
      [ids.capability],
    );
    expect(capability.rows[0]?.usedAt).not.toBeNull();
    const redemptionAudit = await fixture.database.query<{
      action: string;
      requestId: string;
      itemCount: string;
    }>(
      `
        SELECT
          action,
          request_id::text AS "requestId",
          metadata ->> 'item_count' AS "itemCount"
        FROM dirizhor.audit_events
        WHERE action = 'agent_context.redeemed'
          AND target_id = $1::uuid
      `,
      [ids.run],
    );
    expect(redemptionAudit.rows).toEqual([
      {
        action: 'agent_context.redeemed',
        requestId: ids.callerRequest,
        itemCount: '1',
      },
    ]);

    await expect(
      fixture.service.redeemContextBundle(
        ids.run,
        capabilitySecret,
        fixture.redeemRequest,
        ids.callerRequest,
      ),
    ).rejects.toMatchObject({ code: 'capability_used', statusCode: 409 });
  });

  it('does not consume a capability when immutable bytes fail verification', async () => {
    fixture = await createDirectorFixture();
    fixture.documentStore.immutable.set(
      'documents/architecture-v1.md',
      Buffer.from('corrupt bytes', 'utf8'),
    );

    await expect(
      fixture.service.redeemContextBundle(
        ids.run,
        capabilitySecret,
        fixture.redeemRequest,
        ids.callerRequest,
      ),
    ).rejects.toMatchObject({ code: 'context_hash_mismatch', statusCode: 422 });

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

  it('rechecks capability expiry after reading immutable context bytes', async () => {
    fixture = await createDirectorFixture();
    const readImmutable = fixture.documentStore.readImmutable.bind(fixture.documentStore);
    fixture.documentStore.readImmutable = async (storageUri) => {
      const document = await readImmutable(storageUri);
      fixture?.clock.set('2030-01-01T11:30:01.000Z');
      return document;
    };

    await expect(
      fixture.service.redeemContextBundle(
        ids.run,
        capabilitySecret,
        fixture.redeemRequest,
        ids.callerRequest,
      ),
    ).rejects.toMatchObject({ code: 'capability_expired', statusCode: 410 });

    const state = await fixture.database.query<{
      usedAt: string | null;
      auditCount: string;
    }>(
      `
        SELECT
          capability.used_at::text AS "usedAt",
          (
            SELECT count(*)::text
            FROM dirizhor.audit_events
            WHERE action = 'agent_context.redeemed'
              AND target_id = capability.agent_run_id
          ) AS "auditCount"
        FROM dirizhor.agent_capabilities AS capability
        WHERE capability.id = $1::uuid
      `,
      [ids.capability],
    );
    expect(state.rows[0]).toEqual({ usedAt: null, auditCount: '0' });
  });

  it('applies started and completed events atomically with the result and audit inbox', async () => {
    fixture = await createDirectorFixture();
    const started = startedEvent(fixture);
    const completed = completedEvent(fixture);

    await fixture.service.recordGatewayEvent(ids.run, started);
    await fixture.service.recordGatewayEvent(ids.run, completed);

    const run = await fixture.database.query<{
      status: string;
      startedAt: string | null;
      finishedAt: string | null;
    }>(
      `
        SELECT
          status,
          started_at::text AS "startedAt",
          finished_at::text AS "finishedAt"
        FROM dirizhor.agent_runs
        WHERE id = $1::uuid
      `,
      [ids.run],
    );
    expect(run.rows[0]).toMatchObject({
      status: 'completed',
      startedAt: expect.any(String),
      finishedAt: expect.any(String),
    });
    const task = await fixture.database.query<{ status: string }>(
      `SELECT status FROM dirizhor.tasks WHERE id = $1::uuid`,
      [ids.task],
    );
    expect(task.rows[0]?.status).toBe('reviewing');

    const result = await fixture.database.query<{
      contentHash: string;
      sizeBytes: number | string;
      storageUri: string;
      sensitivityLevel: string;
    }>(
      `
        SELECT
          content_hash AS "contentHash",
          size_bytes AS "sizeBytes",
          output_storage_uri AS "storageUri",
          sensitivity_level AS "sensitivityLevel"
        FROM dirizhor.agent_run_results
        WHERE agent_run_id = $1::uuid
      `,
      [ids.run],
    );
    expect(result.rows).toEqual([
      {
        contentHash: completed.result.content_hash,
        sizeBytes: completed.result.size_bytes,
        storageUri: `memory://agent-results/${ids.run}/${completed.result.content_hash}`,
        sensitivityLevel: 'internal',
      },
    ]);
    expect(fixture.documentStore.staged).toHaveLength(1);

    const audit = await fixture.database.query<{ id: string; action: string }>(
      `
        SELECT id::text AS id, action
        FROM dirizhor.audit_events
        WHERE id IN ($1::uuid, $2::uuid)
        ORDER BY created_at, id
      `,
      [ids.startedEvent, ids.completedEvent],
    );
    expect(audit.rows).toHaveLength(2);
    expect(audit.rows.map((row) => row.action).sort()).toEqual([
      'agent_run.completed',
      'agent_run.started',
    ]);
  });

  it('does not stage a completed result before event preflight succeeds', async () => {
    fixture = await createDirectorFixture();
    const outOfOrder = completedEvent(fixture);

    await expect(fixture.service.recordGatewayEvent(ids.run, outOfOrder)).rejects.toMatchObject({
      code: 'invalid_state',
      statusCode: 409,
    });

    expect(fixture.documentStore.staged).toHaveLength(0);
    const result = await fixture.database.query<{ count: string }>(
      `
        SELECT count(*)::text AS count
        FROM dirizhor.agent_run_results
        WHERE agent_run_id = $1::uuid
      `,
      [ids.run],
    );
    expect(result.rows[0]?.count).toBe('0');
  });

  it('accepts an identical event retry without duplicating side effects', async () => {
    fixture = await createDirectorFixture();
    const event = startedEvent(fixture);

    await fixture.service.recordGatewayEvent(ids.run, event);
    await fixture.service.recordGatewayEvent(ids.run, event);

    const audit = await fixture.database.query<{ count: string }>(
      `
        SELECT count(*)::text AS count
        FROM dirizhor.audit_events
        WHERE id = $1::uuid
      `,
      [event.event_id],
    );
    expect(audit.rows[0]?.count).toBe('1');
  });

  it('records and rejects reuse of an event ID with a different canonical hash', async () => {
    fixture = await createDirectorFixture();
    const event = startedEvent(fixture);
    await fixture.service.recordGatewayEvent(ids.run, event);
    const conflicting = resealEvent({ ...event, adapter_version: 'fixture/2.0' });

    let caught: unknown;
    try {
      await fixture.service.recordGatewayEvent(ids.run, conflicting);
    } catch (error) {
      caught = error;
    }
    expect(caught).toBeInstanceOf(DirectorProtocolError);
    expect(caught).toMatchObject({ code: 'idempotency_conflict', statusCode: 409 });

    const conflictAudit = await fixture.database.query<{
      action: string;
      existingHash: string;
      incomingHash: string;
    }>(
      `
        SELECT
          action,
          metadata ->> 'existing_event_hash' AS "existingHash",
          metadata ->> 'incoming_event_hash' AS "incomingHash"
        FROM dirizhor.audit_events
        WHERE action = 'agent_gateway.event_conflict'
      `,
    );
    expect(conflictAudit.rows).toEqual([
      {
        action: 'agent_gateway.event_conflict',
        existingHash: event.event_hash,
        incomingHash: conflicting.event_hash,
      },
    ]);
  });
});
