import { afterEach, describe, expect, it } from 'vitest';

import { HmacCapabilityTokenIssuer } from '../src/capability-token.js';
import { ConfirmationService } from '../src/confirmation-service.js';
import { DecisionService } from '../src/decision-service.js';
import { DirectorProtocolError } from '../src/errors.js';
import type { IdGenerator } from '../src/memory-ports.js';
import { PostgresConfirmationRepository } from '../src/postgres-confirmation-repository.js';
import { PostgresDecisionRepository } from '../src/postgres-decision-repository.js';
import type { AgentGatewayClient } from '../src/task-ports.js';
import {
  createDirectorFixture,
  ids,
  type DirectorFixture,
} from './helpers.js';

const decisionIds = {
  decision: '60000000-0000-4000-8000-000000000001',
  memory: '60000000-0000-4000-8000-000000000002',
  replayDecision: '60000000-0000-4000-8000-000000000003',
  replayMemory: '60000000-0000-4000-8000-000000000004',
  createRequest: '60000000-0000-4000-8000-000000000005',
  readRequest: '60000000-0000-4000-8000-000000000006',
  provenanceRequest: '60000000-0000-4000-8000-000000000007',
  viewer: '60000000-0000-4000-8000-000000000008',
  viewerAssignment: '60000000-0000-4000-8000-000000000009',
  deniedRequest: '60000000-0000-4000-8000-000000000010',
  approvalRequest: '60000000-0000-4000-8000-000000000011',
  approvalConsumeRequest: '60000000-0000-4000-8000-000000000012',
  successor: '60000000-0000-4000-8000-000000000013',
  successorMemory: '60000000-0000-4000-8000-000000000014',
  supersedeRequest: '60000000-0000-4000-8000-000000000015',
  supersedeConsumeRequest: '60000000-0000-4000-8000-000000000016',
  rejectedDecision: '60000000-0000-4000-8000-000000000017',
  rejectedMemory: '60000000-0000-4000-8000-000000000018',
  rejectionPrepareRequest: '60000000-0000-4000-8000-000000000019',
  rejectionConsumeRequest: '60000000-0000-4000-8000-000000000020',
  replaySuccessor: '60000000-0000-4000-8000-000000000021',
  replaySuccessorMemory: '60000000-0000-4000-8000-000000000022',
  tamperedDecision: '60000000-0000-4000-8000-000000000023',
  tamperedMemory: '60000000-0000-4000-8000-000000000024',
  tamperedPrepareRequest: '60000000-0000-4000-8000-000000000025',
  tamperedConsumeRequest: '60000000-0000-4000-8000-000000000026',
  supersedeRejectedDecision: '60000000-0000-4000-8000-000000000027',
  supersedeRejectedMemory: '60000000-0000-4000-8000-000000000028',
  rejectedSuccessor: '60000000-0000-4000-8000-000000000029',
  rejectedSuccessorMemory: '60000000-0000-4000-8000-000000000030',
  supersedeApprovalRequest: '60000000-0000-4000-8000-000000000031',
  supersedeApprovalConsumeRequest: '60000000-0000-4000-8000-000000000032',
  supersedeRejectionPrepareRequest: '60000000-0000-4000-8000-000000000033',
  supersedeRejectionConsumeRequest: '60000000-0000-4000-8000-000000000034',
  rejectTamperedDecision: '60000000-0000-4000-8000-000000000035',
  rejectTamperedMemory: '60000000-0000-4000-8000-000000000036',
  rejectTamperedPrepareRequest: '60000000-0000-4000-8000-000000000037',
  rejectTamperedConsumeRequest: '60000000-0000-4000-8000-000000000038',
} as const;

describe('Decision service', () => {
  let fixture: DirectorFixture | undefined;

  afterEach(async () => {
    await fixture?.close();
    fixture = undefined;
  });

  it('creates a human decision and reconstructs exact source-version provenance', async () => {
    fixture = await createDirectorFixture();
    const service = decisionService(fixture, [
      decisionIds.decision,
      decisionIds.memory,
      decisionIds.replayDecision,
      decisionIds.replayMemory,
    ]);
    const input = {
      project_id: ids.project,
      title: '  Adopt immutable context  ',
      decision_text: '  Use exact document versions for every agent run.  ',
      rationale: '  Reproducible review evidence.  ',
      status: 'proposed' as const,
      sensitivity_level: 'internal' as const,
      relationships: [
        {
          target_type: 'agent_run' as const,
          target_id: ids.run,
          relation_type: 'derived_from' as const,
          description: '  Reviewed AI run  ',
        },
        {
          target_type: 'memory_object' as const,
          target_id: ids.memoryObject,
          relation_type: 'references' as const,
        },
      ],
    };

    const created = await service.createDecision(ids.user, decisionIds.createRequest, input);
    expect(created).toMatchObject({
      id: decisionIds.decision,
      memory_object_id: decisionIds.memory,
      title: 'Adopt immutable context',
      decision_text: 'Use exact document versions for every agent run.',
      rationale: 'Reproducible review evidence.',
      status: 'proposed',
      decided_by_user_id: null,
      decided_at: null,
      sensitivity_level: 'internal',
    });

    const replay = await service.createDecision(ids.user, decisionIds.createRequest, input);
    expect(replay.id).toBe(created.id);

    const read = await service.getDecision(ids.user, decisionIds.readRequest, created.id);
    expect(read).toEqual(created);

    const provenance = await service.getDecisionProvenance(
      ids.user,
      decisionIds.provenanceRequest,
      created.id,
    );
    expect(provenance.provenance_complete).toBe(true);
    expect(provenance.relationships).toHaveLength(2);
    expect(provenance.related_memory_objects).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          id: ids.memoryObject,
          type: 'document',
          title: 'Architecture',
        }),
      ]),
    );
    expect(provenance.agent_runs).toEqual([
      expect.objectContaining({
        id: ids.run,
        task_id: ids.task,
        context_set_hash: expect.stringMatching(/^sha256:[0-9a-f]{64}$/),
      }),
    ]);
    expect(provenance.source_versions).toEqual([
      expect.objectContaining({
        agent_run_id: ids.run,
        memory_object_id: ids.memoryObject,
        document_version_id: ids.documentVersion,
        version_number: 1,
        content_hash: expect.stringMatching(/^sha256:[0-9a-f]{64}$/),
        frozen_sensitivity_level: 'internal',
        current_sensitivity_level: 'internal',
      }),
    ]);
    expect(provenance.audit_events).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          action: 'decision.created',
          target_type: 'decision',
          target_id: decisionIds.decision,
          request_id: decisionIds.createRequest,
        }),
      ]),
    );

    const evidence = await fixture.database.query<{
      memoryType: string;
      authorUserId: string;
      relationshipCount: number | string;
      authorizationDecisionId: string;
      auditDecisionId: string;
      metadata: Record<string, unknown>;
    }>(
      `
        SELECT
          memory.type AS "memoryType",
          memory.author_user_id::text AS "authorUserId",
          (SELECT count(*) FROM dirizhor.relationships WHERE source_id = decision_row.id) AS "relationshipCount",
          authz.id::text AS "authorizationDecisionId",
          audit.authorization_decision_id::text AS "auditDecisionId",
          audit.metadata
        FROM dirizhor.decisions AS decision_row
        JOIN dirizhor.memory_objects AS memory ON memory.id = decision_row.memory_object_id
        JOIN dirizhor.audit_events AS audit
          ON audit.target_type = 'decision' AND audit.target_id = decision_row.id
        JOIN dirizhor.authorization_decisions AS authz
          ON authz.id = audit.authorization_decision_id
        WHERE decision_row.id = $1::uuid AND audit.action = 'decision.created'
      `,
      [decisionIds.decision],
    );
    expect(evidence.rows).toEqual([
      {
        memoryType: 'decision',
        authorUserId: ids.user,
        relationshipCount: 2,
        authorizationDecisionId: evidence.rows[0]?.authorizationDecisionId,
        auditDecisionId: evidence.rows[0]?.authorizationDecisionId,
        metadata: {
          memory_object_id: decisionIds.memory,
          status: 'proposed',
          sensitivity_level: 'internal',
          relationship_count: 2,
        },
      },
    ]);
    expect(JSON.stringify(evidence.rows[0]?.metadata)).not.toContain('immutable context');
  });

  it('denies decision creation without decision.create and leaves no partial rows', async () => {
    fixture = await createDirectorFixture();
    await seedViewer(fixture);
    const service = decisionService(fixture, [decisionIds.decision, decisionIds.memory]);

    await expect(
      service.createDecision(decisionIds.viewer, decisionIds.deniedRequest, {
        project_id: ids.project,
        title: 'Denied decision',
        decision_text: 'Must not persist.',
      }),
    ).rejects.toMatchObject({
      statusCode: 403,
      code: 'access_denied',
      details: { missing_permissions: ['decision.create'] },
    });

    const rows = await fixture.database.query<{ count: number | string }>(
      `SELECT count(*) AS count FROM dirizhor.decisions WHERE id = $1::uuid`,
      [decisionIds.decision],
    );
    expect(Number(rows.rows[0]?.count)).toBe(0);
  });

  it('approves and supersedes decisions only through frozen one-time confirmations', async () => {
    fixture = await createDirectorFixture();
    const service = decisionService(fixture, [
      decisionIds.decision,
      decisionIds.memory,
      decisionIds.successor,
      decisionIds.successorMemory,
      decisionIds.replaySuccessor,
      decisionIds.replaySuccessorMemory,
    ]);
    const confirmations = confirmationService(fixture);
    const proposed = await service.createDecision(ids.user, decisionIds.createRequest, {
      project_id: ids.project,
      title: 'Adopt pilot contract',
      decision_text: 'Use the verified pilot contract.',
      status: 'proposed',
      relationships: [
        {
          target_type: 'memory_object',
          target_id: ids.memoryObject,
          relation_type: 'derived_from',
        },
      ],
    });

    const approvalError = await confirmationRequired(
      service.requestDecisionApproval(
        ids.user,
        decisionIds.approvalRequest,
        proposed.id,
      ),
    );
    expect(approvalError.details).toMatchObject({
      target_type: 'decision',
      target_id: proposed.id,
      payload_hash: expect.stringMatching(/^sha256:[0-9a-f]{64}$/),
    });
    const approvalId = requiredString(approvalError.details.confirmation_id);
    const approval = await confirmations.approveConfirmation(
      ids.user,
      approvalId,
      decisionIds.approvalConsumeRequest,
    );
    expect(approval).toMatchObject({
      operation: 'decision_approve',
      status: 'consumed',
      decided_by_user_id: ids.user,
    });
    const approved = await service.requestDecisionApproval(
      ids.user,
      decisionIds.approvalRequest,
      proposed.id,
    );
    expect(approved).toMatchObject({
      id: proposed.id,
      status: 'approved',
      decided_by_user_id: ids.user,
      decided_at: expect.any(String),
    });

    const supersedeInput = {
      title: 'Adopt verified pilot contract',
      decision_text: 'Use only the machine-readable verified pilot profile.',
      rationale: 'The full contract remains an architectural target.',
      relationships: [
        {
          target_type: 'memory_object' as const,
          target_id: ids.memoryObject,
          relation_type: 'derived_from' as const,
        },
      ],
    };
    const supersedeError = await confirmationRequired(
      service.supersedeDecision(
        ids.user,
        decisionIds.supersedeRequest,
        proposed.id,
        supersedeInput,
      ),
    );
    const supersedeId = requiredString(supersedeError.details.confirmation_id);
    const beforeApproval = await fixture.database.query<{ count: number | string }>(
      `SELECT count(*) AS count FROM dirizhor.decisions WHERE id = $1::uuid`,
      [decisionIds.successor],
    );
    expect(Number(beforeApproval.rows[0]?.count)).toBe(0);

    await confirmations.approveConfirmation(
      ids.user,
      supersedeId,
      decisionIds.supersedeConsumeRequest,
    );
    const superseded = await service.supersedeDecision(
      ids.user,
      decisionIds.supersedeRequest,
      proposed.id,
      supersedeInput,
    );
    expect(superseded.superseded_decision).toMatchObject({
      id: proposed.id,
      status: 'superseded',
    });
    expect(superseded.new_decision).toMatchObject({
      id: decisionIds.successor,
      memory_object_id: decisionIds.successorMemory,
      status: 'approved',
      supersedes_decision_id: proposed.id,
      decided_by_user_id: ids.user,
    });
    const provenance = await service.getDecisionProvenance(
      ids.user,
      decisionIds.provenanceRequest,
      decisionIds.successor,
    );
    expect(provenance.relationships).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          target_type: 'decision',
          target_id: proposed.id,
          relation_type: 'supersedes',
        }),
      ]),
    );
    expect(provenance.audit_events).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ action: 'decision.approved' }),
        expect.objectContaining({ action: 'decision.created' }),
      ]),
    );
  });

  it('rejects an approval confirmation and makes the proposed decision terminal', async () => {
    fixture = await createDirectorFixture();
    const service = decisionService(fixture, [
      decisionIds.rejectedDecision,
      decisionIds.rejectedMemory,
    ]);
    const confirmations = confirmationService(fixture);
    const proposed = await service.createDecision(ids.user, decisionIds.createRequest, {
      project_id: ids.project,
      title: 'Rejected proposal',
      decision_text: 'This proposal must not become authoritative.',
      status: 'proposed',
    });
    const error = await confirmationRequired(
      service.requestDecisionApproval(
        ids.user,
        decisionIds.rejectionPrepareRequest,
        proposed.id,
      ),
    );
    const confirmationId = requiredString(error.details.confirmation_id);
    const rejected = await confirmations.rejectConfirmation(
      ids.user,
      confirmationId,
      decisionIds.rejectionConsumeRequest,
    );
    expect(rejected).toMatchObject({ status: 'rejected', operation: 'decision_approve' });
    const decision = await service.getDecision(
      ids.user,
      decisionIds.readRequest,
      proposed.id,
    );
    expect(decision).toMatchObject({
      status: 'rejected',
      decided_by_user_id: ids.user,
      decided_at: expect.any(String),
    });
  });

  it('rejects a supersede confirmation without changing the approved decision', async () => {
    fixture = await createDirectorFixture();
    const service = decisionService(fixture, [
      decisionIds.supersedeRejectedDecision,
      decisionIds.supersedeRejectedMemory,
      decisionIds.rejectedSuccessor,
      decisionIds.rejectedSuccessorMemory,
    ]);
    const confirmations = confirmationService(fixture);
    const proposed = await service.createDecision(ids.user, decisionIds.createRequest, {
      project_id: ids.project,
      title: 'Keep current decision',
      decision_text: 'This approved decision remains authoritative.',
      status: 'proposed',
    });
    const approvalError = await confirmationRequired(
      service.requestDecisionApproval(
        ids.user,
        decisionIds.supersedeApprovalRequest,
        proposed.id,
      ),
    );
    await confirmations.approveConfirmation(
      ids.user,
      requiredString(approvalError.details.confirmation_id),
      decisionIds.supersedeApprovalConsumeRequest,
    );
    const supersedeError = await confirmationRequired(
      service.supersedeDecision(
        ids.user,
        decisionIds.supersedeRejectionPrepareRequest,
        proposed.id,
        {
          title: 'Unaccepted replacement',
          decision_text: 'This replacement must not be created.',
        },
      ),
    );
    const rejected = await confirmations.rejectConfirmation(
      ids.user,
      requiredString(supersedeError.details.confirmation_id),
      decisionIds.supersedeRejectionConsumeRequest,
    );
    expect(rejected).toMatchObject({ status: 'rejected', operation: 'decision_supersede' });

    const decision = await service.getDecision(
      ids.user,
      decisionIds.readRequest,
      proposed.id,
    );
    expect(decision).toMatchObject({ status: 'approved', supersedes_decision_id: null });
    const successor = await fixture.database.query<{ count: number | string }>(
      `SELECT count(*) AS count FROM dirizhor.decisions WHERE id = $1::uuid`,
      [decisionIds.rejectedSuccessor],
    );
    expect(Number(successor.rows[0]?.count)).toBe(0);
  });

  it('revokes approval when the proposed decision changes after payload freeze', async () => {
    fixture = await createDirectorFixture();
    const service = decisionService(fixture, [
      decisionIds.tamperedDecision,
      decisionIds.tamperedMemory,
    ]);
    const confirmations = confirmationService(fixture);
    const proposed = await service.createDecision(ids.user, decisionIds.createRequest, {
      project_id: ids.project,
      title: 'Frozen proposal',
      decision_text: 'Approve exactly this text.',
      status: 'proposed',
    });
    const error = await confirmationRequired(
      service.requestDecisionApproval(
        ids.user,
        decisionIds.tamperedPrepareRequest,
        proposed.id,
      ),
    );
    const confirmationId = requiredString(error.details.confirmation_id);
    await fixture.database.query(
      `UPDATE dirizhor.decisions SET decision_text = 'Changed after freeze.' WHERE id = $1::uuid`,
      [proposed.id],
    );

    await expect(
      confirmations.approveConfirmation(
        ids.user,
        confirmationId,
        decisionIds.tamperedConsumeRequest,
      ),
    ).rejects.toMatchObject({ statusCode: 409, code: 'conflict' });
    const confirmation = await confirmations.getConfirmation(
      ids.user,
      decisionIds.readRequest,
      confirmationId,
    );
    expect(confirmation.status).toBe('revoked');
    const decision = await service.getDecision(
      ids.user,
      decisionIds.provenanceRequest,
      proposed.id,
    );
    expect(decision).toMatchObject({ status: 'proposed', decided_by_user_id: null });
  });

  it('revokes rejection when the proposed decision changes after payload freeze', async () => {
    fixture = await createDirectorFixture();
    const service = decisionService(fixture, [
      decisionIds.rejectTamperedDecision,
      decisionIds.rejectTamperedMemory,
    ]);
    const confirmations = confirmationService(fixture);
    const proposed = await service.createDecision(ids.user, decisionIds.createRequest, {
      project_id: ids.project,
      title: 'Frozen rejection target',
      decision_text: 'Reject exactly this proposal.',
      status: 'proposed',
    });
    const error = await confirmationRequired(
      service.requestDecisionApproval(
        ids.user,
        decisionIds.rejectTamperedPrepareRequest,
        proposed.id,
      ),
    );
    const confirmationId = requiredString(error.details.confirmation_id);
    await fixture.database.query(
      `UPDATE dirizhor.decisions SET decision_text = 'Changed before rejection.' WHERE id = $1::uuid`,
      [proposed.id],
    );

    await expect(
      confirmations.rejectConfirmation(
        ids.user,
        confirmationId,
        decisionIds.rejectTamperedConsumeRequest,
      ),
    ).rejects.toMatchObject({ statusCode: 409, code: 'conflict' });
    const confirmation = await confirmations.getConfirmation(
      ids.user,
      decisionIds.readRequest,
      confirmationId,
    );
    expect(confirmation.status).toBe('revoked');
    const decision = await service.getDecision(
      ids.user,
      decisionIds.provenanceRequest,
      proposed.id,
    );
    expect(decision).toMatchObject({ status: 'proposed', decided_by_user_id: null });
  });
});

function decisionService(fixture: DirectorFixture, sequence: string[]): DecisionService {
  return new DecisionService({
    repository: new PostgresDecisionRepository(fixture.database),
    idGenerator: new SequenceIds(sequence),
    clock: fixture.clock,
  });
}

function confirmationService(fixture: DirectorFixture): ConfirmationService {
  return new ConfirmationService({
    repository: new PostgresConfirmationRepository(fixture.database),
    gateway: new NoopGateway(),
    capabilityTokens: new HmacCapabilityTokenIssuer(Buffer.alloc(32, 0x61)),
    clock: fixture.clock,
  });
}

async function confirmationRequired(promise: Promise<unknown>): Promise<DirectorProtocolError> {
  try {
    await promise;
  } catch (error) {
    if (error instanceof DirectorProtocolError && error.code === 'requires_confirmation') {
      return error;
    }
    throw error;
  }
  throw new Error('Expected a requires_confirmation error.');
}

function requiredString(value: unknown): string {
  if (typeof value !== 'string') {
    throw new Error('Expected a string confirmation identifier.');
  }
  return value;
}

class NoopGateway implements AgentGatewayClient {
  async dispatch(): Promise<void> {}
}

async function seedViewer(fixture: DirectorFixture): Promise<void> {
  await fixture.database.query(
    `
      INSERT INTO dirizhor.app_users (id, login, display_name, status)
      VALUES ($1::uuid, 'decision-viewer@example.test', 'Decision Viewer', 'active')
    `,
    [decisionIds.viewer],
  );
  await fixture.database.query(
    `
      INSERT INTO dirizhor.role_assignments (
        id, principal_type, principal_id, role_id, scope_type, scope_id, granted_by_user_id
      )
      SELECT
        $1::uuid, 'user', $2::uuid, role.id, 'project', $3::uuid, $4::uuid
      FROM dirizhor.roles AS role
      WHERE role.code = 'project_viewer'
    `,
    [decisionIds.viewerAssignment, decisionIds.viewer, ids.project, ids.user],
  );
}

class SequenceIds implements IdGenerator {
  constructor(private readonly values: string[]) {}

  next(): string {
    const value = this.values.shift();
    if (value === undefined) {
      throw new Error('Test ID sequence is exhausted.');
    }
    return value;
  }
}
