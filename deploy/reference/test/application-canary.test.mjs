import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { chmod, mkdir, mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { test } from 'node:test';

import {
  runApplicationCanary,
  validateApplicationCanaryConfig,
  writeApplicationCanaryEvidence,
} from '../scripts/application-canary.mjs';

const ids = Object.freeze({
  project: '11111111-1111-4111-8111-111111111111',
  user: '22222222-2222-4222-8222-222222222222',
  uploaded: '33333333-3333-4333-8333-333333333333',
  uploadedVersion: '44444444-4444-4444-8444-444444444444',
  internalTask: '55555555-5555-4555-8555-555555555555',
  internalRun: '66666666-6666-4666-8666-666666666666',
  internalResult: '77777777-7777-4777-8777-777777777777',
  saveConfirmation: '88888888-8888-4888-8888-888888888888',
  saved: '99999999-9999-4999-8999-999999999999',
  savedVersion: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
  externalTask: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
  externalRun: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc',
  externalResult: 'dddddddd-dddd-4ddd-8ddd-dddddddddddd',
  externalConfirmation: 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee',
});
const sessionToken = 's'.repeat(43);
const peerFingerprint = Array.from({ length: 32 }, () => 'AA').join(':');
const baselineHeaders = {
  'strict-transport-security': ['max-age=63072000; includeSubDomains'],
  'content-security-policy': [
    "default-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; object-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'",
  ],
  'referrer-policy': ['no-referrer'],
  'x-content-type-options': ['nosniff'],
  'x-frame-options': ['DENY'],
  'permissions-policy': ['camera=(), microphone=(), geolocation=()'],
};

test('config validator requires an isolated persistent canary and exact route semantics', async () => {
  const fixture = await materialFixture();
  try {
    const config = validConfig(fixture);
    assert.doesNotThrow(() => validateApplicationCanaryConfig(config));
    assert.throws(
      () =>
        validateApplicationCanaryConfig({
          ...config,
          application: { ...config.application, dedicated_project: false },
        }),
      /acknowledged dedicated project/,
    );
    assert.throws(
      () =>
        validateApplicationCanaryConfig({
          ...config,
          session: {
            ...config.session,
            expected_project_ids: ['ffffffff-ffff-4fff-8fff-ffffffffffff'],
          },
        }),
      /exact project scope/,
    );
    assert.throws(
      () =>
        validateApplicationCanaryConfig({
          ...config,
          application: {
            ...config.application,
            internal_agent: {
              ...config.application.internal_agent,
              provider_data_profile_version: 'not-internal',
            },
          },
        }),
      /Internal canary agent/,
    );
    assert.throws(
      () => validateApplicationCanaryConfig({ ...config, unsupported: true }),
      /missing or unsupported fields/,
    );
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test('runner completes the primary workflow and emits only bounded evidence', async () => {
  const fixture = await materialFixture();
  try {
    const config = validConfig(fixture);
    const trace = [];
    const report = await runApplicationCanary(config, dependencies(config, {}, trace));
    assert.equal(report.status, 'PASS');
    assert.equal(report.checks.length, 7);
    assert.ok(report.checks.every((check) => check.status === 'PASS'));
    assert.deepEqual(report.registry_updates, [
      {
        id: 'application.primary_canary',
        status: 'PASS',
        observed_at: '2026-08-11T12:00:00.000Z',
        evidence_refs: [
          'run:CHG-123-application-canary-01/application-canary',
          'run:CHG-123/browser-login',
          'artifact:CHG-123/application-audit-review',
          'artifact:CHG-123/infrastructure-log-review',
        ],
      },
    ]);
    assert.match(report.report_sha256, /^sha256:[0-9a-f]{64}$/);
    assert.ok(trace.includes('internal-result-save-replay'));
    assert.ok(trace.includes('external-confirmation-consumed'));

    const serialized = JSON.stringify(report);
    assert.equal(serialized.includes(sessionToken), false);
    assert.equal(serialized.includes('Synthetic internal result content'), false);
    assert.equal(serialized.includes(fixture.root), false);
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test('runner fails closed on an external route that bypasses confirmation', async () => {
  const fixture = await materialFixture();
  try {
    const config = validConfig(fixture);
    const report = await runApplicationCanary(
      config,
      dependencies(config, { externalWithoutConfirmation: true }),
    );
    assert.equal(report.status, 'FAIL');
    assert.deepEqual(
      report.checks.map((check) => [check.id, check.status]),
      [
        ['inputs.protected_files', 'PASS'],
        ['application.project_scope', 'PASS'],
        ['application.document_roundtrip', 'PASS'],
        ['application.internal_agent_run', 'PASS'],
        ['application.result_confirmation_save', 'PASS'],
        ['application.external_confirmation_run', 'FAIL'],
        ['application.timeline_completion', 'NOT_RUN'],
      ],
    );
    assert.deepEqual(
      report.checks.find((check) => check.id === 'application.external_confirmation_run').error,
      {
        code: 'external_agent_confirmation_status',
        message: 'Endpoint returned status 202; expected 428.',
      },
    );
    assert.equal(report.registry_updates[0].status, 'FAIL');
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test('evidence writer requires a new external directory and preserves private modes', async () => {
  const fixture = await materialFixture();
  const workspace = path.join(fixture.root, 'workspace');
  const output = path.join(fixture.root, 'application-evidence');
  await mkdir(workspace);
  try {
    const config = validConfig(fixture);
    const result = await writeApplicationCanaryEvidence({
      config,
      outputDirectory: output,
      workspaceRoot: workspace,
      dependencies: dependencies(config),
    });
    assert.equal(result.report.status, 'PASS');
    assert.equal((await stat(output)).mode & 0o777, 0o700);
    assert.equal((await stat(result.reportPath)).mode & 0o777, 0o600);
    assert.deepEqual(JSON.parse(await readFile(result.reportPath, 'utf8')), result.report);

    await assert.rejects(
      writeApplicationCanaryEvidence({
        config,
        outputDirectory: output,
        workspaceRoot: workspace,
        dependencies: dependencies(config),
      }),
      /EEXIST/,
    );
    await assert.rejects(
      writeApplicationCanaryEvidence({
        config,
        outputDirectory: path.join(workspace, 'evidence'),
        workspaceRoot: workspace,
        dependencies: dependencies(config),
      }),
      /outside the source workspace/,
    );
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

function dependencies(config, behavior = {}, trace = []) {
  let generatedId = 0;
  let monotonic = 0;
  return {
    now: () => new Date('2026-08-11T12:00:00.000Z'),
    monotonicNow: () => {
      monotonic += 100;
      return monotonic;
    },
    randomUUID: () => {
      generatedId += 1;
      return `f0000000-0000-4000-8000-${String(generatedId).padStart(12, '0')}`;
    },
    sleep: async () => {},
    request: syntheticRequest(config, behavior, trace),
  };
}

function syntheticRequest(config, behavior, trace) {
  const marker = config.application.marker;
  const uploadedContent = Buffer.from(
    `# Dirizhor application canary\n\nExecution marker: ${marker}\nThis artifact contains no secrets.\n`,
    'utf8',
  );
  const uploadedHash = sha256(uploadedContent);
  const internalContent = `Synthetic internal result content for ${marker}.`;
  const internalHash = sha256(Buffer.from(internalContent));
  const externalContent = `Synthetic external result content for ${marker}.`;
  const externalHash = sha256(Buffer.from(externalContent));
  const state = {
    internalPolls: 0,
    externalPolls: 0,
    internalOriginRequestId: null,
    externalOriginRequestId: null,
    saveRequestId: null,
    saveBody: null,
    saveApproved: false,
    saved: false,
    externalApproved: false,
  };

  return async (request) => {
    assert.equal(request.url.origin, new URL(config.public.origin).origin);
    const pathname = request.url.pathname;
    const requestId = request.headers['x-request-id'];
    const authenticated = request.headers.cookie !== undefined;
    if (authenticated) {
      assert.equal(
        request.headers.cookie,
        `${config.session.cookie_name}=${sessionToken}`,
      );
      if (!['GET', 'HEAD', 'OPTIONS'].includes(request.method)) {
        assert.equal(request.headers.origin, new URL(config.public.origin).origin);
      }
    }

    if (pathname === '/api/v1/projects' && !authenticated) {
      return response(401, requestId, {
        error: { code: 'unauthorized', message: 'Unauthorized.', details: {}, request_id: requestId },
      });
    }
    if (pathname === '/api/v1/projects') {
      return response(200, requestId, {
        items: [{ id: ids.project, status: 'active' }],
        next_cursor: null,
      });
    }
    if (pathname === '/api/v1/memory-objects:upload') {
      assert.equal(request.method, 'POST');
      assert.ok(Buffer.isBuffer(request.body));
      assert.ok(request.body.includes(Buffer.from(marker)));
      assert.match(request.headers['content-type'], /^multipart\/form-data; boundary=/);
      trace.push('document-uploaded');
      return response(201, requestId, memoryObject({
        id: ids.uploaded,
        versionId: ids.uploadedVersion,
        type: 'document',
        title: `Dirizhor canary ${marker}`,
      }));
    }
    if (pathname === `/api/v1/memory-objects/${ids.uploaded}`) {
      return response(200, requestId, {
        ...memoryObject({
          id: ids.uploaded,
          versionId: ids.uploadedVersion,
          type: 'document',
          title: `Dirizhor canary ${marker}`,
        }),
        current_version: {
          id: ids.uploadedVersion,
          content_hash: uploadedHash,
          file_name: `${marker}.md`,
          file_type: 'text/markdown',
          size_bytes: uploadedContent.length,
        },
      });
    }
    if (pathname === `/api/v1/memory-objects/${ids.saved}`) {
      return response(200, requestId, {
        ...memoryObject({
          id: ids.saved,
          versionId: ids.savedVersion,
          type: 'ai_result',
          title: `Dirizhor canary ${marker} saved result`,
        }),
        current_version: {
          id: ids.savedVersion,
          content_hash: internalHash,
        },
      });
    }
    if (pathname === '/api/v1/memory-objects/search') {
      assert.equal(request.url.searchParams.get('project_id'), ids.project);
      assert.equal(request.url.searchParams.get('q'), marker);
      return response(200, requestId, {
        items: [
          { id: ids.uploaded, type: 'document' },
          ...(state.saved ? [{ id: ids.saved, type: 'ai_result' }] : []),
        ],
        next_cursor: null,
      });
    }
    if (pathname === '/api/v1/tasks' && request.method === 'POST') {
      const body = requestJson(request);
      const internal = body.title.endsWith(' internal');
      return response(201, requestId, {
        id: internal ? ids.internalTask : ids.externalTask,
        project_id: ids.project,
        title: body.title,
        status: 'created',
        result_memory_object_id: null,
      });
    }
    if (pathname === `/api/v1/tasks/${ids.internalTask}/context:search`) {
      return response(200, requestId, {
        task_id: ids.internalTask,
        candidates: [{ memory_object_id: ids.uploaded }],
      });
    }
    if (pathname === `/api/v1/tasks/${ids.internalTask}/agent-runs`) {
      const body = requestJson(request);
      assert.equal(body.agent_type, config.application.internal_agent.agent_type);
      state.internalOriginRequestId = requestId;
      return response(
        202,
        requestId,
        agentRun(config, 'internal', 'queued', requestId),
      );
    }
    if (pathname === `/api/v1/agent-runs/${ids.internalRun}`) {
      state.internalPolls += 1;
      return response(
        200,
        requestId,
        agentRun(
          config,
          'internal',
          state.internalPolls === 1 ? 'running' : 'completed',
          state.internalOriginRequestId,
        ),
      );
    }
    if (pathname === `/api/v1/agent-runs/${ids.internalRun}/result`) {
      return response(200, requestId, {
        id: ids.internalResult,
        agent_run_id: ids.internalRun,
        project_id: ids.project,
        content: internalContent,
        content_type: 'text/plain',
        content_hash: internalHash,
        sensitivity_level: 'internal',
        saved_memory_object_id: state.saved ? ids.saved : null,
        saved_at: state.saved ? '2026-08-11T12:00:00.000Z' : null,
      });
    }
    if (pathname === `/api/v1/agent-runs/${ids.internalRun}/result:save`) {
      if (!state.saveApproved) {
        state.saveRequestId = requestId;
        state.saveBody = Buffer.from(request.body);
        return response(
          428,
          requestId,
          confirmationError(
            requestId,
            ids.saveConfirmation,
            'agent_run_result',
            ids.internalResult,
          ),
        );
      }
      assert.equal(requestId, state.saveRequestId);
      assert.deepEqual(request.body, state.saveBody);
      state.saved = true;
      trace.push('internal-result-save-replay');
      return response(201, requestId, memoryObject({
        id: ids.saved,
        versionId: ids.savedVersion,
        type: 'ai_result',
        title: `Dirizhor canary ${marker} saved result`,
      }));
    }
    if (pathname === `/api/v1/tasks/${ids.externalTask}/agent-runs`) {
      const body = requestJson(request);
      assert.equal(body.agent_type, config.application.external_agent.agent_type);
      state.externalOriginRequestId = requestId;
      if (behavior.externalWithoutConfirmation) {
        return response(202, requestId, agentRun(config, 'external', 'queued', requestId));
      }
      return response(
        428,
        requestId,
        confirmationError(
          requestId,
          ids.externalConfirmation,
          'agent_run',
          ids.externalRun,
        ),
      );
    }
    if (pathname === `/api/v1/agent-runs/${ids.externalRun}`) {
      state.externalPolls += 1;
      return response(
        200,
        requestId,
        agentRun(
          config,
          'external',
          state.externalPolls === 1 ? 'running' : 'completed',
          state.externalOriginRequestId,
        ),
      );
    }
    if (pathname === `/api/v1/agent-runs/${ids.externalRun}/result`) {
      return response(200, requestId, {
        id: ids.externalResult,
        agent_run_id: ids.externalRun,
        project_id: ids.project,
        content: externalContent,
        content_type: 'text/plain',
        content_hash: externalHash,
        sensitivity_level: 'internal',
        saved_memory_object_id: null,
        saved_at: null,
      });
    }
    if (pathname === '/api/v1/confirmations') {
      const pending = state.saveApproved
        ? confirmation(config, 'external', 'pending')
        : confirmation(config, 'save', 'pending');
      return response(200, requestId, { items: [pending], next_cursor: null });
    }
    if (pathname === `/api/v1/confirmations/${ids.saveConfirmation}`) {
      return response(200, requestId, confirmation(config, 'save', 'pending'));
    }
    if (pathname === `/api/v1/confirmations/${ids.externalConfirmation}`) {
      return response(200, requestId, confirmation(config, 'external', 'pending'));
    }
    if (pathname === `/api/v1/confirmations/${ids.saveConfirmation}:approve`) {
      state.saveApproved = true;
      return response(200, requestId, confirmation(config, 'save', 'consumed'));
    }
    if (pathname === `/api/v1/confirmations/${ids.externalConfirmation}:approve`) {
      state.externalApproved = true;
      trace.push('external-confirmation-consumed');
      return response(200, requestId, confirmation(config, 'external', 'consumed'));
    }
    if (pathname === `/api/v1/tasks/${ids.internalTask}`) {
      return response(200, requestId, {
        id: ids.internalTask,
        project_id: ids.project,
        status: state.saved ? 'completed' : 'reviewing',
        result_memory_object_id: state.saved ? ids.saved : null,
        completed_at: state.saved ? '2026-08-11T12:00:00.000Z' : null,
      });
    }
    if (pathname === `/api/v1/tasks/${ids.externalTask}`) {
      assert.equal(state.externalApproved, true);
      return response(200, requestId, {
        id: ids.externalTask,
        project_id: ids.project,
        status: 'reviewing',
        result_memory_object_id: null,
        completed_at: null,
      });
    }
    if (pathname === `/api/v1/tasks/${ids.internalTask}/timeline`) {
      return response(200, requestId, {
        items: [
          { kind: 'agent_run', resource_id: ids.internalRun },
          { kind: 'ai_result', resource_id: ids.saved },
        ],
        next_cursor: null,
      });
    }
    if (pathname === `/api/v1/tasks/${ids.externalTask}/timeline`) {
      return response(200, requestId, {
        items: [{ kind: 'agent_run', resource_id: ids.externalRun }],
        next_cursor: null,
      });
    }
    throw new Error(`Unexpected synthetic request: ${request.method} ${request.url.href}`);
  };
}

function agentRun(config, kind, status, originRequestId) {
  const internal = kind === 'internal';
  const agent = internal
    ? config.application.internal_agent
    : config.application.external_agent;
  return {
    id: internal ? ids.internalRun : ids.externalRun,
    task_id: internal ? ids.internalTask : ids.externalTask,
    project_id: ids.project,
    origin_request_id: originRequestId,
    agent_type: agent.agent_type,
    provider: agent.provider,
    model: agent.model,
    deployment_class: kind,
    provider_data_profile_version: agent.provider_data_profile_version,
    status,
  };
}

function confirmation(config, kind, status) {
  const save = kind === 'save';
  return {
    id: save ? ids.saveConfirmation : ids.externalConfirmation,
    operation: save ? 'ai_result_save' : 'agent_context_share',
    target_type: save ? 'agent_run_result' : 'agent_run',
    target_id: save ? ids.internalResult : ids.externalRun,
    project_id: config.application.project_id,
    status,
    payload_hash: sha256(Buffer.from(`${kind}-confirmation`)),
    decided_by_user_id: status === 'consumed' ? ids.user : null,
    decided_at: status === 'consumed' ? '2026-08-11T12:00:00.000Z' : null,
    consumed_at: status === 'consumed' ? '2026-08-11T12:00:00.000Z' : null,
  };
}

function confirmationError(requestId, confirmationId, targetType, targetId) {
  const kind = targetType === 'agent_run_result' ? 'save' : 'external';
  return {
    error: {
      code: 'requires_confirmation',
      message: 'Confirmation required.',
      request_id: requestId,
      details: {
        confirmation_id: confirmationId,
        target_type: targetType,
        target_id: targetId,
        payload_hash: sha256(Buffer.from(`${kind}-confirmation`)),
        expires_at: '2026-08-11T12:10:00.000Z',
      },
    },
  };
}

function memoryObject({ id, versionId, type, title }) {
  return {
    id,
    project_id: ids.project,
    current_version_id: versionId,
    type,
    title,
    sensitivity_level: 'internal',
    status: 'active',
  };
}

function requestJson(request) {
  assert.ok(Buffer.isBuffer(request.body));
  return JSON.parse(request.body.toString('utf8'));
}

function response(statusCode, requestId, body) {
  return {
    statusCode,
    headers: {
      ...baselineHeaders,
      'content-type': ['application/json; charset=utf-8'],
      'x-request-id': [requestId],
    },
    body: JSON.stringify(body),
    tls: {
      authorized: true,
      protocol: 'TLSv1.3',
      peerFingerprint256: peerFingerprint,
    },
  };
}

function validConfig(fixture) {
  return {
    schema_version: 1,
    execution_id: 'CHG-123-application-canary-01',
    environment: 'production-pilot',
    request_timeout_ms: 10_000,
    public: {
      origin: 'https://director.example.test',
      ca_path: null,
    },
    session: {
      cookie_name: '__Host-dirizhor_session',
      token_file: fixture.sessionToken,
      expected_project_ids: [ids.project],
      browser_flow_evidence_ref: 'run:CHG-123/browser-login',
    },
    application: {
      dedicated_project: true,
      persistent_artifacts_acknowledged: true,
      project_id: ids.project,
      marker: 'chg-123-canary-01',
      poll_interval_ms: 250,
      poll_timeout_ms: 5_000,
      internal_agent: {
        agent_type: 'canary_internal',
        provider: 'internal-ai',
        model: 'internal-model',
        provider_data_profile_version: null,
      },
      external_agent: {
        agent_type: 'canary_external',
        provider: 'openai',
        model: 'external-model',
        provider_data_profile_version: 'approved-profile-v1',
      },
    },
    external_evidence: {
      audit_review_ref: 'artifact:CHG-123/application-audit-review',
      infrastructure_log_review_ref: 'artifact:CHG-123/infrastructure-log-review',
    },
  };
}

async function materialFixture() {
  const root = await mkdtemp(path.join(tmpdir(), 'dirizhor-application-canary-'));
  const sessionTokenPath = path.join(root, 'session-token');
  await writeFile(sessionTokenPath, `${sessionToken}\n`, { mode: 0o600 });
  await chmod(sessionTokenPath, 0o600);
  return { root, sessionToken: sessionTokenPath };
}

function sha256(value) {
  return `sha256:${createHash('sha256').update(value).digest('hex')}`;
}
