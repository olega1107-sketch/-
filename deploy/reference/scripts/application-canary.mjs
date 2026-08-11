#!/usr/bin/env node

import { createHash, randomUUID } from 'node:crypto';
import { chmod, mkdir, readFile, stat, writeFile } from 'node:fs/promises';
import net from 'node:net';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import {
  CanaryFailure,
  CanaryTransportError,
  requestHttps,
} from './target-canary.mjs';

const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
const defaultWorkspaceRoot = path.resolve(scriptDirectory, '../../..');
const uuidPattern = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-8][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$/;
const identifierPattern = /^[A-Za-z0-9][A-Za-z0-9._:/#-]{0,255}$/;
const routeIdentifierPattern = /^[a-z][a-z0-9_-]{1,63}$/;
const markerPattern = /^[a-z0-9](?:[a-z0-9-]{6,62}[a-z0-9])$/;
const evidenceReferencePattern = /^(?:alert|artifact|backup|change|dashboard|run|ticket):[A-Za-z0-9][A-Za-z0-9._:/#-]{0,240}$/;
const sha256Pattern = /^sha256:[0-9a-f]{64}$/;
const protectedModes = new Set([0o400, 0o440, 0o600, 0o640]);
const securityHeaders = Object.freeze({
  'strict-transport-security': 'max-age=63072000; includeSubDomains',
  'content-security-policy': "default-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; object-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'",
  'referrer-policy': 'no-referrer',
  'x-content-type-options': 'nosniff',
  'x-frame-options': 'DENY',
  'permissions-policy': 'camera=(), microphone=(), geolocation=()',
});

export function validateApplicationCanaryConfig(document) {
  assertObject(document, 'config');
  assertExactKeys(
    document,
    [
      'schema_version',
      'execution_id',
      'environment',
      'request_timeout_ms',
      'public',
      'session',
      'application',
      'external_evidence',
    ],
    'config',
  );
  if (document.schema_version !== 1) {
    throw new Error('Application canary config schema_version must be 1.');
  }
  assertIdentifier(document.execution_id, 'execution_id');
  assertIdentifier(document.environment, 'environment');
  if (
    !Number.isSafeInteger(document.request_timeout_ms) ||
    document.request_timeout_ms < 1_000 ||
    document.request_timeout_ms > 30_000
  ) {
    throw new Error('request_timeout_ms must be an integer from 1000 through 30000.');
  }

  validatePublicConfig(document.public);
  validateSessionConfig(document.session);
  validateApplicationConfig(document.application);
  validateExternalEvidence(document.external_evidence);
  validateCrossFieldConfig(document);
  return document;
}

export async function runApplicationCanary(config, dependencies = {}) {
  validateApplicationCanaryConfig(config);
  const runtime = {
    now: dependencies.now ?? (() => new Date()),
    monotonicNow: dependencies.monotonicNow ?? (() => Date.now()),
    request: dependencies.request ?? requestHttps,
    readFile: dependencies.readFile ?? readFile,
    stat: dependencies.stat ?? stat,
    randomUUID: dependencies.randomUUID ?? randomUUID,
    sleep: dependencies.sleep ?? ((milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds))),
  };
  const startedAt = isoNow(runtime.now);
  const state = {
    materialReader: createMaterialReader(runtime),
    materials: null,
    uploadedMemoryObjectId: null,
    uploadedVersionId: null,
    internalTaskId: null,
    internalRunId: null,
    internalResultId: null,
    internalResultHash: null,
    savedMemoryObjectId: null,
    externalTaskId: null,
    externalRunId: null,
    externalResultHash: null,
  };
  const checks = [];
  const definitions = [
    ['inputs.protected_files', [], () => checkProtectedFiles(config, state)],
    ['application.project_scope', ['inputs.protected_files'], () => checkProjectScope(config, runtime, state)],
    ['application.document_roundtrip', ['application.project_scope'], () => checkDocumentRoundtrip(config, runtime, state)],
    ['application.internal_agent_run', ['application.document_roundtrip'], () => checkInternalAgentRun(config, runtime, state)],
    ['application.result_confirmation_save', ['application.internal_agent_run'], () => checkResultConfirmationSave(config, runtime, state)],
    ['application.external_confirmation_run', ['application.result_confirmation_save'], () => checkExternalConfirmationRun(config, runtime, state)],
    ['application.timeline_completion', ['application.external_confirmation_run'], () => checkTimelineCompletion(config, runtime, state)],
  ];

  for (const [id, required, execute] of definitions) {
    if (required.some((requiredId) => checks.find((check) => check.id === requiredId)?.status !== 'PASS')) {
      checks.push(notRunCheck(id));
      continue;
    }
    checks.push(await executeCheck(id, execute, runtime));
  }

  const completedAt = isoNow(runtime.now);
  const status = checks.every((check) => check.status === 'PASS') ? 'PASS' : 'FAIL';
  const evidenceRef = `run:${config.execution_id}/application-canary`;
  const report = {
    schema_version: 1,
    execution_id: config.execution_id,
    environment: config.environment,
    artifact_marker: config.application.marker,
    started_at: startedAt,
    completed_at: completedAt,
    status,
    evidence_ref: evidenceRef,
    checks,
    registry_updates: [applicationRegistryUpdate(checks, config, evidenceRef)],
    external_evidence_refs: [
      config.session.browser_flow_evidence_ref,
      config.external_evidence.audit_review_ref,
      config.external_evidence.infrastructure_log_review_ref,
    ],
    limitations: [
      'Creates persistent tagged artifacts in the dedicated canary project; no public delete API is used.',
      'Does not retry mutating requests after transport ambiguity.',
      'References, but does not read, the browser, audit, and infrastructure-log evidence artifacts.',
      'Does not execute application failure-mode or dependency-readiness checks.',
    ],
  };
  return {
    ...report,
    report_sha256: canonicalHash(report),
  };
}

export async function writeApplicationCanaryEvidence({
  config,
  outputDirectory,
  workspaceRoot = defaultWorkspaceRoot,
  dependencies,
}) {
  validateApplicationCanaryConfig(config);
  const resolvedOutput = path.resolve(outputDirectory);
  const resolvedWorkspace = path.resolve(workspaceRoot);
  if (isWithin(resolvedOutput, resolvedWorkspace)) {
    throw new Error('Application canary output directory must be outside the source workspace.');
  }
  await mkdir(resolvedOutput, { mode: 0o700 });
  await chmod(resolvedOutput, 0o700);
  const report = await runApplicationCanary(config, dependencies);
  const reportPath = path.join(resolvedOutput, 'application-canary-evidence.json');
  await writeFile(reportPath, `${JSON.stringify(report, null, 2)}\n`, {
    encoding: 'utf8',
    flag: 'wx',
    mode: 0o600,
  });
  await chmod(reportPath, 0o600);
  return { report, reportPath };
}

async function executeCheck(id, execute, runtime) {
  const began = runtime.monotonicNow();
  try {
    const observations = await execute();
    return {
      id,
      status: 'PASS',
      observed_at: isoNow(runtime.now),
      duration_ms: duration(runtime.monotonicNow() - began),
      observations,
      error: null,
    };
  } catch (error) {
    return {
      id,
      status: 'FAIL',
      observed_at: isoNow(runtime.now),
      duration_ms: duration(runtime.monotonicNow() - began),
      observations: null,
      error: reportedFailure(error),
    };
  }
}

function notRunCheck(id) {
  return {
    id,
    status: 'NOT_RUN',
    observed_at: null,
    duration_ms: 0,
    observations: null,
    error: {
      code: 'dependency_failed',
      message: 'A required earlier application canary check did not pass.',
    },
  };
}

async function checkProtectedFiles(config, state) {
  const specifications = [
    ...(config.public.ca_path === null
      ? []
      : [{ label: 'public_ca', path: config.public.ca_path, protected: false, kind: 'pem' }]),
    {
      label: 'session_token',
      path: config.session.token_file,
      protected: true,
      kind: 'session-token',
    },
  ];
  const materials = new Map();
  const files = [];
  for (const specification of specifications) {
    const material = await state.materialReader.read(specification);
    materials.set(specification.label, material);
    files.push({
      label: specification.label,
      mode: modeString(material.mode),
      protected: specification.protected,
    });
  }
  const sessionToken = secretText(materials.get('session_token').content, 'session token');
  if (!/^[A-Za-z0-9_-]{43}$/.test(sessionToken)) {
    fail('session_token_invalid', 'Session token does not match the opaque token contract.');
  }
  state.materials = {
    sessionToken,
    ca: materials.get('public_ca')?.content,
  };
  return { file_count: files.length, files };
}

async function checkProjectScope(config, runtime, state) {
  const anonymousRequestId = runtime.randomUUID();
  const anonymous = await apiRequest(config, runtime, state, '/api/v1/projects?limit=100', {
    method: 'GET',
    authenticated: false,
    requestId: anonymousRequestId,
    expectedStatus: 401,
  });
  const anonymousPayload = jsonObject(anonymous.body, 'project_collection_public_json');
  assertPublicError(anonymousPayload, anonymousRequestId, 'unauthorized', 'project_collection_public');

  const response = await apiJson(config, runtime, state, '/api/v1/projects?limit=100', {
    method: 'GET',
    expectedStatus: 200,
    failureCode: 'project_collection_status',
  });
  if (!Array.isArray(response.payload.items) || !('next_cursor' in response.payload)) {
    fail('project_collection_shape', 'Project collection response has an invalid shape.');
  }
  if (response.payload.next_cursor !== null) {
    fail('project_collection_incomplete', 'Application canary cannot prove the complete project set.');
  }
  const observedIds = response.payload.items.map((item) => {
    if (!isObject(item) || typeof item.id !== 'string' || !uuidPattern.test(item.id)) {
      fail('project_collection_shape', 'Project collection contains an invalid project.');
    }
    return item.id.toLowerCase();
  });
  const expectedIds = config.session.expected_project_ids.map((value) => value.toLowerCase());
  if (!sameStringSet(observedIds, expectedIds)) {
    fail('project_scope_mismatch', 'Canary identity received an unexpected project set.');
  }
  const project = response.payload.items.find(
    (item) => isObject(item) && String(item.id).toLowerCase() === config.application.project_id.toLowerCase(),
  );
  if (!isObject(project) || project.status !== 'active') {
    fail('canary_project_inactive', 'The dedicated application canary project is not active.');
  }
  return {
    anonymous_request_rejected: true,
    expected_project_count: expectedIds.length,
    observed_project_count: observedIds.length,
    exact_project_set: true,
    dedicated_project_active: true,
  };
}

async function checkDocumentRoundtrip(config, runtime, state) {
  const marker = config.application.marker;
  const title = `Dirizhor canary ${marker}`;
  const fileName = `${marker}.md`;
  const content = Buffer.from(
    `# Dirizhor application canary\n\nExecution marker: ${marker}\nThis artifact contains no secrets.\n`,
    'utf8',
  );
  const contentHash = sha256(content);
  const boundary = `dirizhor-canary-${runtime.randomUUID().replaceAll('-', '')}`;
  const body = multipartBody(
    boundary,
    [
      ['project_id', config.application.project_id],
      ['type', 'document'],
      ['title', title],
      ['summary', `Automated application canary ${marker}`],
      ['keywords', marker],
      ['keywords', 'application-canary'],
      ['sensitivity_level', 'internal'],
    ],
    { field: 'file', fileName, mediaType: 'text/markdown', content },
  );
  const uploaded = await apiJson(config, runtime, state, '/api/v1/memory-objects:upload', {
    method: 'POST',
    body,
    headers: { 'content-type': `multipart/form-data; boundary=${boundary}` },
    expectedStatus: 201,
    failureCode: 'document_upload_status',
  });
  assertMemoryObjectSummary(uploaded.payload, {
    projectId: config.application.project_id,
    type: 'document',
    title,
    sensitivityLevel: 'internal',
  }, 'document_upload_shape');
  if (typeof uploaded.payload.current_version_id !== 'string' || !uuidPattern.test(uploaded.payload.current_version_id)) {
    fail('document_upload_shape', 'Uploaded document is missing a current version identifier.');
  }
  state.uploadedMemoryObjectId = uploaded.payload.id;
  state.uploadedVersionId = uploaded.payload.current_version_id;

  const read = await apiJson(
    config,
    runtime,
    state,
    `/api/v1/memory-objects/${encodeURIComponent(state.uploadedMemoryObjectId)}`,
    { method: 'GET', expectedStatus: 200, failureCode: 'document_read_status' },
  );
  assertMemoryObjectSummary(read.payload, {
    projectId: config.application.project_id,
    type: 'document',
    title,
    sensitivityLevel: 'internal',
  }, 'document_read_shape');
  if (read.payload.id !== state.uploadedMemoryObjectId || !isObject(read.payload.current_version)) {
    fail('document_read_shape', 'Document read response does not identify the uploaded version.');
  }
  const version = read.payload.current_version;
  if (
    version.id !== state.uploadedVersionId ||
    version.content_hash !== contentHash ||
    version.file_name !== fileName ||
    version.file_type !== 'text/markdown' ||
    version.size_bytes !== content.length
  ) {
    fail('document_integrity_mismatch', 'Document read response does not match the uploaded bytes.');
  }

  const searchPath = `/api/v1/memory-objects/search?${new URLSearchParams({
    project_id: config.application.project_id,
    q: marker,
    type: 'document',
    limit: '100',
  })}`;
  const search = await apiJson(config, runtime, state, searchPath, {
    method: 'GET',
    expectedStatus: 200,
    failureCode: 'document_search_status',
  });
  assertPageContains(search.payload, state.uploadedMemoryObjectId, 'document_search_shape');
  return {
    upload_status_code: 201,
    read_status_code: 200,
    search_status_code: 200,
    content_hash: contentHash,
    content_size_bytes: content.length,
    exact_version_roundtrip: true,
  };
}

async function checkInternalAgentRun(config, runtime, state) {
  const marker = config.application.marker;
  const task = await createTask(config, runtime, state, 'internal');
  state.internalTaskId = task.id;

  const contextSearch = await apiJson(
    config,
    runtime,
    state,
    `/api/v1/tasks/${encodeURIComponent(state.internalTaskId)}/context:search`,
    {
      method: 'POST',
      body: jsonBody({ query: marker, types: ['document'], limit: 20 }),
      expectedStatus: 200,
      failureCode: 'task_context_search_status',
    },
  );
  if (
    contextSearch.payload.task_id !== state.internalTaskId ||
    !Array.isArray(contextSearch.payload.candidates) ||
    !contextSearch.payload.candidates.some(
      (candidate) => isObject(candidate) && candidate.memory_object_id === state.uploadedMemoryObjectId,
    )
  ) {
    fail('task_context_search_shape', 'Task context search did not return the uploaded document.');
  }

  const requestId = runtime.randomUUID();
  const created = await apiJson(
    config,
    runtime,
    state,
    `/api/v1/tasks/${encodeURIComponent(state.internalTaskId)}/agent-runs`,
    {
      method: 'POST',
      requestId,
      body: jsonBody(
        agentRunBody(
          config.application.marker,
          config.application.internal_agent,
          state,
          'internal',
        ),
      ),
      expectedStatus: 202,
      failureCode: 'internal_agent_create_status',
    },
  );
  assertAgentRun(created.payload, config, state.internalTaskId, requestId, config.application.internal_agent, 'internal');
  if (created.payload.status !== 'queued') {
    fail('internal_agent_initial_status', 'Internal agent run was not accepted in queued state.');
  }
  state.internalRunId = created.payload.id;

  const terminal = await pollAgentRun(
    config,
    runtime,
    state,
    state.internalRunId,
    state.internalTaskId,
    requestId,
    config.application.internal_agent,
    'internal',
  );
  const result = await readAgentResult(config, runtime, state, state.internalRunId, 'internal');
  state.internalResultId = result.payload.id;
  state.internalResultHash = result.payload.content_hash;
  if (result.payload.saved_memory_object_id !== null || result.payload.saved_at !== null) {
    fail('internal_result_already_saved', 'Fresh internal agent result was unexpectedly already saved.');
  }
  const taskAfterRun = await readTask(config, runtime, state, state.internalTaskId);
  if (taskAfterRun.status !== 'reviewing' || taskAfterRun.result_memory_object_id !== null) {
    fail('internal_task_review_state', 'Internal task did not enter the expected reviewing state.');
  }
  return {
    task_created: true,
    context_candidate_found: true,
    deployment_class: 'internal',
    agent_type: config.application.internal_agent.agent_type,
    provider: config.application.internal_agent.provider,
    model: config.application.internal_agent.model,
    terminal_status: 'completed',
    poll_attempts: terminal.attempts,
    result_content_hash: state.internalResultHash,
    result_content_recorded: false,
  };
}

async function checkResultConfirmationSave(config, runtime, state) {
  const savePayload = {
    title: `Dirizhor canary ${config.application.marker} saved result`,
    summary: `Confirmed result for application canary ${config.application.marker}`,
    keywords: [config.application.marker, 'application-canary'],
    relationships: [
      {
        target_type: 'memory_object',
        target_id: state.uploadedMemoryObjectId,
        relation_type: 'derived_from',
      },
    ],
  };
  const encodedPayload = jsonBody(savePayload);
  const requestId = runtime.randomUUID();
  const requested = await apiJson(
    config,
    runtime,
    state,
    `/api/v1/agent-runs/${encodeURIComponent(state.internalRunId)}/result:save`,
    {
      method: 'POST',
      requestId,
      body: encodedPayload,
      expectedStatus: 428,
      failureCode: 'result_save_confirmation_status',
    },
  );
  const confirmation = confirmationFromError(
    requested.payload,
    requestId,
    'agent_run_result',
    state.internalResultId,
    'result_save_confirmation_shape',
    runtime.now(),
  );
  await verifyPendingConfirmation(
    config,
    runtime,
    state,
    confirmation,
    'ai_result_save',
  );
  await approveConfirmation(config, runtime, state, confirmation.id, 'ai_result_save');

  const saved = await apiJson(
    config,
    runtime,
    state,
    `/api/v1/agent-runs/${encodeURIComponent(state.internalRunId)}/result:save`,
    {
      method: 'POST',
      requestId,
      body: encodedPayload,
      expectedStatus: 201,
      failureCode: 'result_save_replay_status',
    },
  );
  assertMemoryObjectSummary(saved.payload, {
    projectId: config.application.project_id,
    type: 'ai_result',
    title: savePayload.title,
    sensitivityLevel: 'internal',
  }, 'saved_result_shape');
  if (typeof saved.payload.current_version_id !== 'string' || !uuidPattern.test(saved.payload.current_version_id)) {
    fail('saved_result_shape', 'Saved AI result is missing a current version identifier.');
  }
  state.savedMemoryObjectId = saved.payload.id;

  const savedRead = await apiJson(
    config,
    runtime,
    state,
    `/api/v1/memory-objects/${encodeURIComponent(state.savedMemoryObjectId)}`,
    { method: 'GET', expectedStatus: 200, failureCode: 'saved_result_read_status' },
  );
  if (
    savedRead.payload.id !== state.savedMemoryObjectId ||
    !isObject(savedRead.payload.current_version) ||
    savedRead.payload.current_version.content_hash !== state.internalResultHash
  ) {
    fail('saved_result_integrity_mismatch', 'Saved AI result hash does not match the temporary result.');
  }
  const resultAfterSave = await readAgentResult(
    config,
    runtime,
    state,
    state.internalRunId,
    'internal',
  );
  if (
    resultAfterSave.payload.saved_memory_object_id !== state.savedMemoryObjectId ||
    typeof resultAfterSave.payload.saved_at !== 'string'
  ) {
    fail('result_save_link_missing', 'Temporary result does not identify the confirmed saved memory object.');
  }
  return {
    confirmation_required: true,
    confirmation_operation: 'ai_result_save',
    confirmation_payload_hash: confirmation.payloadHash,
    approved_and_consumed: true,
    exact_request_replayed: true,
    saved_result_content_hash: state.internalResultHash,
  };
}

async function checkExternalConfirmationRun(config, runtime, state) {
  const task = await createTask(config, runtime, state, 'external');
  state.externalTaskId = task.id;
  const requestId = runtime.randomUUID();
  const requested = await apiJson(
    config,
    runtime,
    state,
    `/api/v1/tasks/${encodeURIComponent(state.externalTaskId)}/agent-runs`,
    {
      method: 'POST',
      requestId,
      body: jsonBody(
        agentRunBody(
          config.application.marker,
          config.application.external_agent,
          state,
          'external',
        ),
      ),
      expectedStatus: 428,
      failureCode: 'external_agent_confirmation_status',
    },
  );
  const confirmation = confirmationFromError(
    requested.payload,
    requestId,
    'agent_run',
    null,
    'external_agent_confirmation_shape',
    runtime.now(),
  );
  state.externalRunId = confirmation.targetId;
  await verifyPendingConfirmation(
    config,
    runtime,
    state,
    confirmation,
    'agent_context_share',
  );
  await approveConfirmation(config, runtime, state, confirmation.id, 'agent_context_share');

  const terminal = await pollAgentRun(
    config,
    runtime,
    state,
    state.externalRunId,
    state.externalTaskId,
    requestId,
    config.application.external_agent,
    'external',
  );
  const result = await readAgentResult(config, runtime, state, state.externalRunId, 'external');
  state.externalResultHash = result.payload.content_hash;
  const taskAfterRun = await readTask(config, runtime, state, state.externalTaskId);
  if (taskAfterRun.status !== 'reviewing' || taskAfterRun.result_memory_object_id !== null) {
    fail('external_task_review_state', 'External task did not enter the expected reviewing state.');
  }
  return {
    confirmation_required: true,
    confirmation_operation: 'agent_context_share',
    confirmation_payload_hash: confirmation.payloadHash,
    frozen_payload_excluded_from_public_api: true,
    approved_and_consumed: true,
    deployment_class: 'external',
    agent_type: config.application.external_agent.agent_type,
    provider: config.application.external_agent.provider,
    model: config.application.external_agent.model,
    provider_data_profile_version: config.application.external_agent.provider_data_profile_version,
    terminal_status: 'completed',
    poll_attempts: terminal.attempts,
    result_content_hash: state.externalResultHash,
    result_content_recorded: false,
  };
}

async function checkTimelineCompletion(config, runtime, state) {
  const internalTask = await readTask(config, runtime, state, state.internalTaskId);
  if (
    internalTask.status !== 'completed' ||
    internalTask.result_memory_object_id !== state.savedMemoryObjectId ||
    typeof internalTask.completed_at !== 'string'
  ) {
    fail('internal_task_completion', 'Internal task did not complete with the saved result.');
  }
  const externalTask = await readTask(config, runtime, state, state.externalTaskId);
  if (externalTask.status !== 'reviewing' || externalTask.result_memory_object_id !== null) {
    fail('external_task_completion', 'External task has an unexpected post-run state.');
  }

  const internalTimeline = await readTimeline(config, runtime, state, state.internalTaskId);
  assertTimelineContains(internalTimeline, 'agent_run', state.internalRunId, 'internal_timeline');
  assertTimelineContains(internalTimeline, 'ai_result', state.savedMemoryObjectId, 'internal_timeline');
  const externalTimeline = await readTimeline(config, runtime, state, state.externalTaskId);
  assertTimelineContains(externalTimeline, 'agent_run', state.externalRunId, 'external_timeline');

  const searchPath = `/api/v1/memory-objects/search?${new URLSearchParams({
    project_id: config.application.project_id,
    q: config.application.marker,
    limit: '100',
  })}`;
  const search = await apiJson(config, runtime, state, searchPath, {
    method: 'GET',
    expectedStatus: 200,
    failureCode: 'final_memory_search_status',
  });
  assertPageContains(search.payload, state.uploadedMemoryObjectId, 'final_memory_search_shape');
  assertPageContains(search.payload, state.savedMemoryObjectId, 'final_memory_search_shape');

  return {
    internal_task_status: 'completed',
    external_task_status: 'reviewing',
    internal_timeline_items: internalTimeline.items.length,
    external_timeline_items: externalTimeline.items.length,
    uploaded_and_saved_results_searchable: true,
    browser_flow_evidence_ref: config.session.browser_flow_evidence_ref,
    audit_review_evidence_ref: config.external_evidence.audit_review_ref,
    infrastructure_log_review_evidence_ref:
      config.external_evidence.infrastructure_log_review_ref,
  };
}

async function createTask(config, runtime, state, kind) {
  const payload = {
    project_id: config.application.project_id,
    title: `Dirizhor canary ${config.application.marker} ${kind}`,
    user_request: `Execute the ${kind} application canary for marker ${config.application.marker}.`,
  };
  const response = await apiJson(config, runtime, state, '/api/v1/tasks', {
    method: 'POST',
    body: jsonBody(payload),
    expectedStatus: 201,
    failureCode: `${kind}_task_create_status`,
  });
  if (
    typeof response.payload.id !== 'string' ||
    !uuidPattern.test(response.payload.id) ||
    response.payload.project_id !== config.application.project_id ||
    response.payload.title !== payload.title ||
    response.payload.status !== 'created' ||
    response.payload.result_memory_object_id !== null
  ) {
    fail(`${kind}_task_create_shape`, `${capitalized(kind)} task create response is invalid.`);
  }
  return response.payload;
}

function agentRunBody(marker, agent, state, kind) {
  return {
    agent_type: agent.agent_type,
    purpose: `Dirizhor ${kind} canary`,
    instructions: `Return a concise acknowledgement containing marker ${marker}.`,
    context: [
      {
        memory_object_id: state.uploadedMemoryObjectId,
        document_version_id: state.uploadedVersionId,
        access_reason: `Application canary ${kind} context`,
      },
    ],
  };
}

async function pollAgentRun(config, runtime, state, runId, taskId, originRequestId, agent, deploymentClass) {
  const deadline = runtime.monotonicNow() + config.application.poll_timeout_ms;
  let attempts = 0;
  for (;;) {
    attempts += 1;
    const response = await apiJson(
      config,
      runtime,
      state,
      `/api/v1/agent-runs/${encodeURIComponent(runId)}`,
      { method: 'GET', expectedStatus: 200, failureCode: `${deploymentClass}_agent_read_status` },
    );
    assertAgentRun(response.payload, config, taskId, originRequestId, agent, deploymentClass);
    if (response.payload.id !== runId) {
      fail(`${deploymentClass}_agent_identity`, 'Agent run read returned a different run.');
    }
    if (response.payload.status === 'completed') {
      return { run: response.payload, attempts };
    }
    if (response.payload.status === 'failed' || response.payload.status === 'cancelled') {
      fail(`${deploymentClass}_agent_terminal_failure`, `${capitalized(deploymentClass)} agent run ended unsuccessfully.`);
    }
    if (response.payload.status === 'awaiting_user_confirmation') {
      fail(`${deploymentClass}_agent_confirmation_stalled`, `${capitalized(deploymentClass)} agent run remained awaiting confirmation.`);
    }
    if (!['queued', 'running'].includes(response.payload.status)) {
      fail(`${deploymentClass}_agent_status`, `${capitalized(deploymentClass)} agent run returned an invalid status.`);
    }
    if (runtime.monotonicNow() >= deadline) {
      fail(`${deploymentClass}_agent_timeout`, `${capitalized(deploymentClass)} agent run did not complete before timeout.`);
    }
    await runtime.sleep(config.application.poll_interval_ms);
  }
}

function assertAgentRun(payload, config, taskId, originRequestId, agent, deploymentClass) {
  if (
    !isObject(payload) ||
    typeof payload.id !== 'string' ||
    !uuidPattern.test(payload.id) ||
    payload.task_id !== taskId ||
    payload.project_id !== config.application.project_id ||
    payload.origin_request_id !== originRequestId ||
    payload.agent_type !== agent.agent_type ||
    payload.provider !== agent.provider ||
    payload.model !== agent.model ||
    payload.deployment_class !== deploymentClass ||
    payload.provider_data_profile_version !== agent.provider_data_profile_version
  ) {
    fail(`${deploymentClass}_agent_route_mismatch`, `${capitalized(deploymentClass)} agent run does not match the approved route.`);
  }
}

async function readAgentResult(config, runtime, state, runId, kind) {
  const response = await apiJson(
    config,
    runtime,
    state,
    `/api/v1/agent-runs/${encodeURIComponent(runId)}/result`,
    { method: 'GET', expectedStatus: 200, failureCode: `${kind}_result_read_status` },
  );
  const payload = response.payload;
  if (
    typeof payload.id !== 'string' ||
    !uuidPattern.test(payload.id) ||
    payload.agent_run_id !== runId ||
    payload.project_id !== config.application.project_id ||
    typeof payload.content !== 'string' ||
    payload.content.length === 0 ||
    !payload.content.includes(config.application.marker) ||
    typeof payload.content_type !== 'string' ||
    payload.content_type.length === 0 ||
    !sha256Pattern.test(payload.content_hash) ||
    payload.content_hash !== sha256(Buffer.from(payload.content, 'utf8')) ||
    payload.sensitivity_level !== 'internal'
  ) {
    fail(`${kind}_result_integrity`, `${capitalized(kind)} agent result failed its integrity contract.`);
  }
  return response;
}

async function verifyPendingConfirmation(config, runtime, state, confirmation, operation) {
  const listPath = `/api/v1/confirmations?${new URLSearchParams({
    project_id: config.application.project_id,
    status: 'pending',
    limit: '100',
  })}`;
  const inbox = await apiJson(config, runtime, state, listPath, {
    method: 'GET',
    expectedStatus: 200,
    failureCode: 'confirmation_inbox_status',
  });
  if (!Array.isArray(inbox.payload.items) || !('next_cursor' in inbox.payload)) {
    fail('confirmation_inbox_shape', 'Confirmation inbox response has an invalid shape.');
  }
  const listed = inbox.payload.items.find(
    (item) => isObject(item) && item.id === confirmation.id,
  );
  if (!isObject(listed) || listed.status !== 'pending' || 'frozen_payload' in listed) {
    fail('confirmation_inbox_shape', 'Pending confirmation is missing or exposes frozen payload.');
  }

  const read = await apiJson(
    config,
    runtime,
    state,
    `/api/v1/confirmations/${encodeURIComponent(confirmation.id)}`,
    { method: 'GET', expectedStatus: 200, failureCode: 'confirmation_read_status' },
  );
  if (
    read.payload.id !== confirmation.id ||
    read.payload.operation !== operation ||
    read.payload.target_type !== confirmation.targetType ||
    read.payload.target_id !== confirmation.targetId ||
    read.payload.project_id !== config.application.project_id ||
    read.payload.status !== 'pending' ||
    read.payload.payload_hash !== confirmation.payloadHash ||
    'frozen_payload' in read.payload
  ) {
    fail('confirmation_read_shape', 'Pending confirmation does not match the frozen request metadata.');
  }
}

async function approveConfirmation(config, runtime, state, confirmationId, operation) {
  const approved = await apiJson(
    config,
    runtime,
    state,
    `/api/v1/confirmations/${encodeURIComponent(confirmationId)}:approve`,
    { method: 'POST', expectedStatus: 200, failureCode: 'confirmation_approve_status' },
  );
  if (
    approved.payload.id !== confirmationId ||
    approved.payload.operation !== operation ||
    approved.payload.status !== 'consumed' ||
    typeof approved.payload.decided_by_user_id !== 'string' ||
    !uuidPattern.test(approved.payload.decided_by_user_id) ||
    typeof approved.payload.decided_at !== 'string' ||
    typeof approved.payload.consumed_at !== 'string'
  ) {
    fail('confirmation_approve_shape', 'Approved confirmation was not atomically consumed.');
  }
}

function confirmationFromError(payload, requestId, targetType, targetId, failureCode, observedAt) {
  if (!isObject(payload.error) || payload.error.code !== 'requires_confirmation' || payload.error.request_id !== requestId) {
    fail(failureCode, 'Public API did not return the expected confirmation error.');
  }
  const details = payload.error.details;
  if (
    !isObject(details) ||
    typeof details.confirmation_id !== 'string' ||
    !uuidPattern.test(details.confirmation_id) ||
    details.target_type !== targetType ||
    typeof details.target_id !== 'string' ||
    !uuidPattern.test(details.target_id) ||
    (targetId !== null && details.target_id !== targetId) ||
    typeof details.payload_hash !== 'string' ||
    !sha256Pattern.test(details.payload_hash) ||
    typeof details.expires_at !== 'string' ||
    !Number.isFinite(Date.parse(details.expires_at)) ||
    Date.parse(details.expires_at) <= observedAt.getTime()
  ) {
    fail(failureCode, 'Confirmation error details do not match the expected operation.');
  }
  return {
    id: details.confirmation_id,
    targetType: details.target_type,
    targetId: details.target_id,
    payloadHash: details.payload_hash,
  };
}

async function readTask(config, runtime, state, taskId) {
  const response = await apiJson(
    config,
    runtime,
    state,
    `/api/v1/tasks/${encodeURIComponent(taskId)}`,
    { method: 'GET', expectedStatus: 200, failureCode: 'task_read_status' },
  );
  if (
    response.payload.id !== taskId ||
    response.payload.project_id !== config.application.project_id ||
    typeof response.payload.status !== 'string'
  ) {
    fail('task_read_shape', 'Task read response has an invalid shape.');
  }
  return response.payload;
}

async function readTimeline(config, runtime, state, taskId) {
  const response = await apiJson(
    config,
    runtime,
    state,
    `/api/v1/tasks/${encodeURIComponent(taskId)}/timeline?limit=100`,
    { method: 'GET', expectedStatus: 200, failureCode: 'task_timeline_status' },
  );
  if (!Array.isArray(response.payload.items) || response.payload.next_cursor !== null) {
    fail('task_timeline_shape', 'Task timeline is invalid or incomplete.');
  }
  return response.payload;
}

function assertTimelineContains(timeline, kind, resourceId, failureCode) {
  if (
    !timeline.items.some(
      (item) => isObject(item) && item.kind === kind && item.resource_id === resourceId,
    )
  ) {
    fail(failureCode, `Task timeline does not contain the expected ${kind} entry.`);
  }
}

function assertMemoryObjectSummary(payload, expected, failureCode) {
  if (
    !isObject(payload) ||
    typeof payload.id !== 'string' ||
    !uuidPattern.test(payload.id) ||
    payload.project_id !== expected.projectId ||
    payload.type !== expected.type ||
    payload.title !== expected.title ||
    payload.sensitivity_level !== expected.sensitivityLevel ||
    payload.status !== 'active'
  ) {
    fail(failureCode, 'Memory object response does not match the application canary artifact.');
  }
}

function assertPageContains(payload, memoryObjectId, failureCode) {
  if (
    !Array.isArray(payload.items) ||
    !('next_cursor' in payload) ||
    !payload.items.some((item) => isObject(item) && item.id === memoryObjectId)
  ) {
    fail(failureCode, 'Memory object search did not return the expected canary artifact.');
  }
}

async function apiJson(config, runtime, state, pathname, options) {
  const response = await apiRequest(config, runtime, state, pathname, options);
  return {
    response,
    payload: jsonObject(response.body, options.failureCode ?? 'api_response_json'),
  };
}

async function apiRequest(config, runtime, state, pathname, options) {
  if (state.materials === null) {
    fail('canary_state_invalid', 'Application canary materials are unavailable.');
  }
  const requestId = options.requestId ?? runtime.randomUUID();
  if (!uuidPattern.test(requestId)) {
    fail('request_id_invalid', 'Canary request ID generator returned a non-UUID value.');
  }
  const body = options.body;
  const authenticated = options.authenticated !== false;
  const mutating = !['GET', 'HEAD', 'OPTIONS'].includes(options.method);
  const headers = {
    'user-agent': 'dirizhor-application-canary/1',
    accept: 'application/json',
    'x-request-id': requestId,
    ...(authenticated
      ? { cookie: `${config.session.cookie_name}=${state.materials.sessionToken}` }
      : {}),
    ...(authenticated && mutating
      ? { origin: new URL(config.public.origin).origin }
      : {}),
    ...(body === undefined ? {} : { 'content-length': String(body.length) }),
    ...((body !== undefined && options.headers?.['content-type'] === undefined)
      ? { 'content-type': 'application/json' }
      : {}),
    ...(options.headers ?? {}),
  };
  const response = await runtime.request({
    url: new URL(pathname, config.public.origin),
    method: options.method,
    headers,
    ...(body === undefined ? {} : { body }),
    ...(state.materials.ca === undefined ? {} : { ca: state.materials.ca }),
    timeoutMs: config.request_timeout_ms,
    maxBodyBytes: 4 * 1024 * 1024,
  });
  assertStatus(response, options.expectedStatus, options.failureCode ?? 'api_response_status');
  assertTls(response);
  assertSecurityHeaders(response);
  requireHeaderPrefix(response, 'content-type', 'application/json', 'api_content_type');
  requireHeaderValue(response, 'x-request-id', requestId, 'api_request_id');
  return response;
}

function multipartBody(boundary, fields, file) {
  const chunks = [];
  for (const [name, value] of fields) {
    chunks.push(Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="${name}"\r\n\r\n${value}\r\n`, 'utf8'));
  }
  chunks.push(
    Buffer.from(
      `--${boundary}\r\nContent-Disposition: form-data; name="${file.field}"; filename="${file.fileName}"\r\nContent-Type: ${file.mediaType}\r\n\r\n`,
      'utf8',
    ),
    file.content,
    Buffer.from(`\r\n--${boundary}--\r\n`, 'utf8'),
  );
  return Buffer.concat(chunks);
}

function jsonBody(value) {
  return Buffer.from(JSON.stringify(value), 'utf8');
}

function assertPublicError(payload, requestId, errorCode, failureCode) {
  if (!isObject(payload.error) || payload.error.code !== errorCode || payload.error.request_id !== requestId) {
    fail(failureCode, 'Public API returned an unexpected protocol error.');
  }
}

function assertStatus(response, expected, failureCode) {
  if (response.statusCode !== expected) {
    fail(failureCode, `Endpoint returned status ${response.statusCode}; expected ${expected}.`);
  }
}

function assertTls(response) {
  if (
    !isObject(response.tls) ||
    response.tls.authorized !== true ||
    !['TLSv1.2', 'TLSv1.3'].includes(response.tls.protocol) ||
    typeof response.tls.peerFingerprint256 !== 'string' ||
    !/^([0-9A-F]{2}:){31}[0-9A-F]{2}$/i.test(response.tls.peerFingerprint256)
  ) {
    fail('tls_contract_failed', 'Endpoint did not prove an authorized TLS 1.2+ peer.');
  }
}

function assertSecurityHeaders(response) {
  for (const [name, expected] of Object.entries(securityHeaders)) {
    requireHeaderValue(response, name, expected, 'edge_security_headers');
  }
}

function requireHeaderValue(response, name, expected, failureCode) {
  if (!headerValues(response, name).includes(expected)) {
    fail(failureCode, `Response header ${name} does not match the target contract.`);
  }
}

function requireHeaderPrefix(response, name, prefix, failureCode) {
  if (!headerValues(response, name).some((value) => value.startsWith(prefix))) {
    fail(failureCode, `Response header ${name} does not match the target contract.`);
  }
}

function headerValues(response, name) {
  const value = response.headers?.[name.toLowerCase()];
  return Array.isArray(value) ? value : typeof value === 'string' ? [value] : [];
}

function createMaterialReader(runtime) {
  const cache = new Map();
  return {
    read(specification) {
      const key = `${specification.kind}:${specification.protected ? 'protected' : 'public'}:${specification.path}`;
      if (!cache.has(key)) {
        cache.set(key, readMaterial(specification, runtime));
      }
      return cache.get(key);
    },
  };
}

async function readMaterial(specification, runtime) {
  let metadata;
  let content;
  try {
    [metadata, content] = await Promise.all([
      runtime.stat(specification.path),
      runtime.readFile(specification.path),
    ]);
  } catch {
    fail('material_unreadable', `${specification.label} could not be read.`);
  }
  if (!metadata.isFile()) {
    fail('material_not_file', `${specification.label} is not a regular file.`);
  }
  const mode = metadata.mode & 0o777;
  if (specification.protected) {
    if (!protectedModes.has(mode)) {
      fail('material_permissions', `${specification.label} must use mode 0400, 0440, 0600, or 0640.`);
    }
  } else if ((mode & 0o022) !== 0) {
    fail('material_permissions', `${specification.label} must not be group- or world-writable.`);
  }
  if (!Buffer.isBuffer(content) || content.length === 0 || content.length > 1024 * 1024) {
    fail('material_size', `${specification.label} has an invalid size.`);
  }
  return { content, mode };
}

function secretText(content, label) {
  let value = content.toString('utf8');
  if (value.endsWith('\n')) {
    value = value.slice(0, -1);
  }
  if (value.length === 0 || value.includes('\n') || value.includes('\r') || value.includes('\0')) {
    fail('secret_format', `${label} must contain exactly one non-empty line.`);
  }
  return value;
}

function applicationRegistryUpdate(checks, config, evidenceRef) {
  const passed = checks.every((check) => check.status === 'PASS');
  const observedAt = checks
    .map((check) => check.observed_at)
    .filter((value) => typeof value === 'string')
    .sort()
    .at(-1) ?? null;
  return {
    id: 'application.primary_canary',
    status: passed ? 'PASS' : 'FAIL',
    observed_at: observedAt,
    evidence_refs: [
      evidenceRef,
      config.session.browser_flow_evidence_ref,
      config.external_evidence.audit_review_ref,
      config.external_evidence.infrastructure_log_review_ref,
    ],
  };
}

function reportedFailure(error) {
  if (error instanceof CanaryFailure) {
    return { code: error.code, message: error.message };
  }
  if (error instanceof CanaryTransportError) {
    return {
      code: error.code,
      message: `HTTPS transport failed (${error.transportCode}).`,
    };
  }
  return { code: 'unexpected_error', message: 'Application canary check failed unexpectedly.' };
}

function fail(code, message) {
  throw new CanaryFailure(code, message);
}

function validatePublicConfig(value) {
  assertObject(value, 'public');
  assertExactKeys(value, ['origin', 'ca_path'], 'public');
  exactHttpsOrigin(value.origin, 'public.origin');
  nullableAbsolutePath(value.ca_path, 'public.ca_path');
}

function validateSessionConfig(value) {
  assertObject(value, 'session');
  assertExactKeys(
    value,
    ['cookie_name', 'token_file', 'expected_project_ids', 'browser_flow_evidence_ref'],
    'session',
  );
  if (value.cookie_name !== '__Host-dirizhor_session') {
    throw new Error('session.cookie_name must match the protected Director cookie.');
  }
  absolutePath(value.token_file, 'session.token_file');
  if (
    !Array.isArray(value.expected_project_ids) ||
    value.expected_project_ids.length !== 1 ||
    typeof value.expected_project_ids[0] !== 'string' ||
    !uuidPattern.test(value.expected_project_ids[0])
  ) {
    throw new Error('session.expected_project_ids must contain exactly one dedicated project UUID.');
  }
  evidenceReference(value.browser_flow_evidence_ref, 'session.browser_flow_evidence_ref');
}

function validateApplicationConfig(value) {
  assertObject(value, 'application');
  assertExactKeys(
    value,
    [
      'dedicated_project',
      'persistent_artifacts_acknowledged',
      'project_id',
      'marker',
      'poll_interval_ms',
      'poll_timeout_ms',
      'internal_agent',
      'external_agent',
    ],
    'application',
  );
  if (value.dedicated_project !== true || value.persistent_artifacts_acknowledged !== true) {
    throw new Error('Application canary requires an acknowledged dedicated project.');
  }
  if (typeof value.project_id !== 'string' || !uuidPattern.test(value.project_id)) {
    throw new Error('application.project_id must be a UUID.');
  }
  if (typeof value.marker !== 'string' || !markerPattern.test(value.marker)) {
    throw new Error('application.marker must be a lowercase 8 through 64 character marker.');
  }
  if (
    !Number.isSafeInteger(value.poll_interval_ms) ||
    value.poll_interval_ms < 250 ||
    value.poll_interval_ms > 5_000
  ) {
    throw new Error('application.poll_interval_ms must be an integer from 250 through 5000.');
  }
  if (
    !Number.isSafeInteger(value.poll_timeout_ms) ||
    value.poll_timeout_ms < 5_000 ||
    value.poll_timeout_ms > 15 * 60_000 ||
    value.poll_timeout_ms <= value.poll_interval_ms
  ) {
    throw new Error('application.poll_timeout_ms must exceed the interval and be from 5000 through 900000.');
  }
  validateAgent(value.internal_agent, 'application.internal_agent', 'internal');
  validateAgent(value.external_agent, 'application.external_agent', 'external');
  if (value.internal_agent.agent_type === value.external_agent.agent_type) {
    throw new Error('Internal and external canary agent types must differ.');
  }
}

function validateAgent(value, name, deploymentClass) {
  assertObject(value, name);
  assertExactKeys(
    value,
    ['agent_type', 'provider', 'model', 'provider_data_profile_version'],
    name,
  );
  if (typeof value.agent_type !== 'string' || !routeIdentifierPattern.test(value.agent_type)) {
    throw new Error(`${name}.agent_type is invalid.`);
  }
  if (typeof value.provider !== 'string' || !routeIdentifierPattern.test(value.provider)) {
    throw new Error(`${name}.provider is invalid.`);
  }
  if (
    value.model !== null &&
    (typeof value.model !== 'string' || value.model.length === 0 || value.model.length > 255)
  ) {
    throw new Error(`${name}.model must be null or a non-empty string.`);
  }
  if (deploymentClass === 'internal' && value.provider_data_profile_version !== null) {
    throw new Error('Internal canary agent cannot set a provider data profile version.');
  }
  if (
    deploymentClass === 'external' &&
    (typeof value.provider_data_profile_version !== 'string' ||
      value.provider_data_profile_version.length === 0 ||
      value.provider_data_profile_version.length > 255)
  ) {
    throw new Error('External canary agent requires a provider data profile version.');
  }
}

function validateExternalEvidence(value) {
  assertObject(value, 'external_evidence');
  assertExactKeys(
    value,
    ['audit_review_ref', 'infrastructure_log_review_ref'],
    'external_evidence',
  );
  evidenceReference(value.audit_review_ref, 'external_evidence.audit_review_ref');
  evidenceReference(
    value.infrastructure_log_review_ref,
    'external_evidence.infrastructure_log_review_ref',
  );
}

function validateCrossFieldConfig(config) {
  if (
    config.session.expected_project_ids[0].toLowerCase() !==
    config.application.project_id.toLowerCase()
  ) {
    throw new Error('Application canary project must be the session identity exact project scope.');
  }
  const ownEvidenceRef = `run:${config.execution_id}/application-canary`;
  const externalRefs = [
    config.session.browser_flow_evidence_ref,
    config.external_evidence.audit_review_ref,
    config.external_evidence.infrastructure_log_review_ref,
  ];
  if (new Set(externalRefs).size !== externalRefs.length) {
    throw new Error('Application canary external evidence references must be unique.');
  }
  if (externalRefs.includes(ownEvidenceRef)) {
    throw new Error('External evidence must not point to the application canary report itself.');
  }
}

function exactHttpsOrigin(value, name) {
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new Error(`${name} must be an absolute HTTPS URL.`);
  }
  if (
    url.protocol !== 'https:' ||
    url.username.length > 0 ||
    url.password.length > 0 ||
    url.pathname !== '/' ||
    url.search.length > 0 ||
    url.hash.length > 0 ||
    net.isIP(url.hostname) !== 0
  ) {
    throw new Error(`${name} must be an exact HTTPS DNS origin.`);
  }
  return url;
}

function nullableAbsolutePath(value, name) {
  if (value !== null) {
    absolutePath(value, name);
  }
}

function absolutePath(value, name) {
  if (
    typeof value !== 'string' ||
    !path.isAbsolute(value) ||
    value.includes('\0') ||
    value.includes('\n') ||
    value.includes('\r')
  ) {
    throw new Error(`${name} must be an absolute file path.`);
  }
}

function evidenceReference(value, name) {
  if (typeof value !== 'string' || !evidenceReferencePattern.test(value)) {
    throw new Error(`${name} must be an opaque evidence reference.`);
  }
}

function assertIdentifier(value, name) {
  if (
    typeof value !== 'string' ||
    !identifierPattern.test(value) ||
    value.startsWith('replace-')
  ) {
    throw new Error(`${name} must be an opaque identifier.`);
  }
}

function assertObject(value, name) {
  if (!isObject(value)) {
    throw new Error(`${name} must be an object.`);
  }
}

function assertExactKeys(value, expected, name) {
  const actual = Object.keys(value).sort();
  const sortedExpected = [...expected].sort();
  if (JSON.stringify(actual) !== JSON.stringify(sortedExpected)) {
    throw new Error(`${name} contains missing or unsupported fields.`);
  }
}

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function jsonObject(value, failureCode) {
  let parsed;
  try {
    parsed = JSON.parse(value);
  } catch {
    fail(failureCode, 'Endpoint returned malformed JSON.');
  }
  if (!isObject(parsed)) {
    fail(failureCode, 'Endpoint returned a non-object JSON document.');
  }
  return parsed;
}

function sameStringSet(left, right) {
  return (
    new Set(left).size === left.length &&
    new Set(right).size === right.length &&
    [...left].sort().join('\0') === [...right].sort().join('\0')
  );
}

function sha256(value) {
  return `sha256:${createHash('sha256').update(value).digest('hex')}`;
}

function canonicalHash(value) {
  return sha256(Buffer.from(JSON.stringify(canonicalize(value)), 'utf8'));
}

function canonicalize(value) {
  if (Array.isArray(value)) {
    return value.map(canonicalize);
  }
  if (isObject(value)) {
    return Object.fromEntries(
      Object.keys(value)
        .sort()
        .map((key) => [key, canonicalize(value[key])]),
    );
  }
  return value;
}

function isWithin(candidate, root) {
  const relative = path.relative(root, candidate);
  return relative === '' || (!relative.startsWith('..') && !path.isAbsolute(relative));
}

function duration(value) {
  return Number.isFinite(value) && value > 0 ? Math.round(value) : 0;
}

function isoNow(now) {
  const value = now();
  if (!(value instanceof Date) || !Number.isFinite(value.getTime())) {
    throw new Error('Canary clock returned an invalid time.');
  }
  return value.toISOString();
}

function modeString(mode) {
  return mode.toString(8).padStart(4, '0');
}

function capitalized(value) {
  return `${value.slice(0, 1).toUpperCase()}${value.slice(1)}`;
}

async function main(argv) {
  if (argv.length !== 2) {
    throw new Error(
      'Usage: node scripts/application-canary.mjs <new-output-directory> <config.json>',
    );
  }
  let config;
  try {
    config = JSON.parse(await readFile(argv[1], 'utf8'));
  } catch {
    throw new Error('Application canary config could not be read.');
  }
  const result = await writeApplicationCanaryEvidence({
    config,
    outputDirectory: argv[0],
  });
  process.stdout.write(
    `${JSON.stringify(
      {
        status: result.report.status,
        execution_id: result.report.execution_id,
        artifact_marker: result.report.artifact_marker,
        report_sha256: result.report.report_sha256,
        pass: result.report.checks.filter((check) => check.status === 'PASS').length,
        fail: result.report.checks.filter((check) => check.status === 'FAIL').length,
        not_run: result.report.checks.filter((check) => check.status === 'NOT_RUN').length,
        evidence_file: path.basename(result.reportPath),
      },
      null,
      2,
    )}\n`,
  );
  process.exitCode = result.report.status === 'PASS' ? 0 : 1;
}

if (
  process.argv[1] !== undefined &&
  pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url
) {
  void main(process.argv.slice(2)).catch((error) => {
    const message = error instanceof Error ? error.message : 'Application canary failed.';
    process.stderr.write(`Application canary failed: ${message}\n`);
    process.exitCode = 2;
  });
}
