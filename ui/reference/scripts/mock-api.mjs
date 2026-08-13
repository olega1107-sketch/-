import { createServer } from 'node:http';

const projectId = '10000000-0000-4000-8000-000000000002';
const now = Date.now();
const port = Number(process.env.DIRECTOR_MOCK_PORT ?? 8444);
const mockUserId = '10000000-0000-4000-8000-000000000009';
const sourceMemoryId = '70000000-0000-4000-8000-000000000001';
const sourceVersionId = '70000000-0000-4000-8000-000000000002';
const sourceRunId = '70000000-0000-4000-8000-000000000003';
const decisions = new Map();
const confirmationEffects = new Map();

const base = {
  project_id: projectId,
  requested_by_user_id: mockUserId,
  decided_by_user_id: null,
  authorization_decision_id: '30000000-0000-4000-8000-000000000001',
  request_id: '40000000-0000-4000-8000-000000000001',
  status: 'pending',
  payload_hash: `sha256:${'a'.repeat(64)}`,
  created_at: new Date(now - 4 * 60_000).toISOString(),
  expires_at: new Date(now + 11 * 60_000).toISOString(),
  decided_at: null,
  consumed_at: null,
};

const pending = [
  {
    ...base,
    id: '50000000-0000-4000-8000-000000000001',
    operation: 'agent_context_share',
    target_type: 'agent_run',
    target_id: '60000000-0000-4000-8000-000000000001',
    summary: 'Передать 3 внутренних документа агенту архитектурного анализа',
  },
  {
    ...base,
    id: '50000000-0000-4000-8000-000000000002',
    operation: 'ai_result_save',
    target_type: 'agent_run_result',
    target_id: '60000000-0000-4000-8000-000000000002',
    summary: 'Сохранить результат проверки архитектуры в корпоративную память проекта',
    created_at: new Date(now - 7 * 60_000).toISOString(),
    expires_at: new Date(now + 8 * 60_000).toISOString(),
  },
  {
    ...base,
    id: '50000000-0000-4000-8000-000000000003',
    operation: 'bulk_context_share',
    target_type: 'agent_run',
    target_id: '60000000-0000-4000-8000-000000000003',
    summary: 'Разрешить обработку расширенного набора материалов для подготовки сводного решения по инфраструктуре и модели доступа',
    created_at: new Date(now - 10 * 60_000).toISOString(),
    expires_at: new Date(now + 5 * 60_000).toISOString(),
  },
];

const server = createServer(async (request, response) => {
  const url = new URL(request.url ?? '/', 'http://127.0.0.1:8444');
  response.setHeader('content-type', 'application/json; charset=utf-8');
  response.setHeader('x-request-id', request.headers['x-request-id'] ?? 'mock-request');
  if (request.method === 'GET' && url.pathname === '/api/v1/projects') {
    return json(response, 200, {
      items: [{
        id: projectId,
        title: 'Архитектура знаний',
        description: 'Основной проект',
        status: 'active',
        owner_user_id: base.requested_by_user_id,
        created_at: new Date(now - 86_400_000).toISOString(),
        updated_at: new Date(now).toISOString(),
        archived_at: null,
      }],
      next_cursor: null,
    });
  }
  if (request.method === 'GET' && url.pathname === '/api/v1/confirmations') {
    const status = url.searchParams.get('status') ?? 'pending';
    return json(response, 200, { items: status === 'pending' ? pending : [], next_cursor: null });
  }
  if (request.method === 'POST' && url.pathname === '/api/v1/decisions') {
    const input = await jsonBody(request);
    const id = crypto.randomUUID();
    const decision = {
      id,
      memory_object_id: crypto.randomUUID(),
      project_id: input.project_id,
      topic_id: null,
      title: input.title,
      decision_text: input.decision_text,
      rationale: input.rationale ?? null,
      status: input.status ?? 'draft',
      supersedes_decision_id: null,
      decided_by_user_id: null,
      decided_at: null,
      sensitivity_level: input.sensitivity_level ?? 'internal',
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
      relationships: input.relationships ?? [],
    };
    decisions.set(id, decision);
    return json(response, 201, decision);
  }
  const approvalMatch = url.pathname.match(/^\/api\/v1\/decisions\/([^/]+):approve$/);
  if (request.method === 'POST' && approvalMatch !== null) {
    const id = approvalMatch[1];
    const target = decisions.get(id) ?? sampleDecision(id);
    decisions.set(id, target);
    if (target.status === 'approved') return json(response, 200, target);
    const confirmation = decisionConfirmation('decision_approve', id, `Утвердить решение «${target.title}»`);
    pending.unshift(confirmation);
    confirmationEffects.set(confirmation.id, { operation: 'decision_approve', targetId: id });
    return confirmationRequired(response, confirmation);
  }
  const supersedeMatch = url.pathname.match(/^\/api\/v1\/decisions\/([^/]+):supersede$/);
  if (request.method === 'POST' && supersedeMatch !== null) {
    const id = supersedeMatch[1];
    const target = decisions.get(id) ?? { ...sampleDecision(id), status: 'approved' };
    decisions.set(id, target);
    if (target.status !== 'approved') {
      return json(response, 409, { error: { code: 'conflict', message: 'Решение не утверждено.' } });
    }
    const input = await jsonBody(request);
    const confirmation = decisionConfirmation('decision_supersede', id, `Заменить решение «${target.title}»`);
    pending.unshift(confirmation);
    confirmationEffects.set(confirmation.id, { operation: 'decision_supersede', targetId: id, input });
    return confirmationRequired(response, confirmation);
  }
  const provenanceMatch = url.pathname.match(/^\/api\/v1\/decisions\/([^/]+)\/provenance$/);
  if (request.method === 'GET' && provenanceMatch !== null) {
    const decision = decisions.get(provenanceMatch[1]) ?? sampleDecision(provenanceMatch[1]);
    return json(response, 200, provenance(decision));
  }
  const decision = url.pathname.match(/^\/api\/v1\/confirmations\/([^/]+):(approve|reject)$/);
  if (request.method === 'POST' && decision !== null) {
    const confirmation = pending.find((item) => item.id === decision[1]);
    if (confirmation === undefined) return json(response, 404, { error: { code: 'not_found' } });
    const action = decision[2];
    pending.splice(pending.indexOf(confirmation), 1);
    applyConfirmationEffect(confirmation.id, action);
    return json(response, 200, {
      ...confirmation,
      status: action === 'approve' ? 'consumed' : 'rejected',
      decided_by_user_id: base.requested_by_user_id,
      decided_at: new Date().toISOString(),
      consumed_at: action === 'approve' ? new Date().toISOString() : null,
    });
  }
  return json(response, 404, { error: { code: 'not_found', message: 'Mock route not found.' } });
});

server.listen(port, '127.0.0.1', () => {
  process.stdout.write(`Mock Director API listening at http://127.0.0.1:${port}\n`);
});

function json(response, status, body) {
  response.statusCode = status;
  response.end(JSON.stringify(body));
}

function decisionConfirmation(operation, targetId, summary) {
  return {
    ...base,
    id: crypto.randomUUID(),
    operation,
    target_type: 'decision',
    target_id: targetId,
    request_id: crypto.randomUUID(),
    payload_hash: `sha256:${crypto.randomUUID().replaceAll('-', '').padEnd(64, '0')}`,
    summary,
    created_at: new Date().toISOString(),
    expires_at: new Date(Date.now() + 15 * 60_000).toISOString(),
  };
}

function confirmationRequired(response, confirmation) {
  return json(response, 428, {
    error: {
      code: 'requires_confirmation',
      message: 'Операция требует подтверждения.',
      details: {
        confirmation_id: confirmation.id,
        target_type: confirmation.target_type,
        target_id: confirmation.target_id,
        payload_hash: confirmation.payload_hash,
        expires_at: confirmation.expires_at,
      },
    },
  });
}

function applyConfirmationEffect(confirmationId, action) {
  const effect = confirmationEffects.get(confirmationId);
  if (effect === undefined) return;
  confirmationEffects.delete(confirmationId);
  const target = decisions.get(effect.targetId);
  if (target === undefined) return;
  const decidedAt = new Date().toISOString();
  if (effect.operation === 'decision_approve') {
    decisions.set(effect.targetId, {
      ...target,
      status: action === 'approve' ? 'approved' : 'rejected',
      decided_by_user_id: mockUserId,
      decided_at: decidedAt,
      updated_at: decidedAt,
    });
    return;
  }
  if (action !== 'approve') return;
  const successorId = crypto.randomUUID();
  decisions.set(effect.targetId, { ...target, status: 'superseded', updated_at: decidedAt });
  decisions.set(successorId, {
    id: successorId,
    memory_object_id: crypto.randomUUID(),
    project_id: target.project_id,
    topic_id: target.topic_id,
    title: effect.input.title,
    decision_text: effect.input.decision_text,
    rationale: effect.input.rationale ?? null,
    status: 'approved',
    supersedes_decision_id: target.id,
    decided_by_user_id: mockUserId,
    decided_at: decidedAt,
    sensitivity_level: effect.input.sensitivity_level ?? 'internal',
    created_at: decidedAt,
    updated_at: decidedAt,
    relationships: [
      ...(effect.input.relationships ?? []),
      { target_type: 'decision', target_id: target.id, relation_type: 'supersedes', description: null },
    ],
  });
}

async function jsonBody(request) {
  const chunks = [];
  for await (const chunk of request) chunks.push(chunk);
  return JSON.parse(Buffer.concat(chunks).toString('utf8'));
}

function sampleDecision(id) {
  return {
    id,
    memory_object_id: '70000000-0000-4000-8000-000000000004',
    project_id: projectId,
    topic_id: null,
    title: 'Использовать неизменяемый контекст для запусков AI',
    decision_text: 'Каждый запуск агента получает только явно выбранные версии документов. Контекст фиксируется до dispatch и не меняется при повторе запроса.',
    rationale: 'Это позволяет воспроизвести результат и проверить основание решения.',
    status: 'proposed',
    supersedes_decision_id: null,
    decided_by_user_id: null,
    decided_at: null,
    sensitivity_level: 'internal',
    created_at: new Date(now - 3_600_000).toISOString(),
    updated_at: new Date(now - 3_600_000).toISOString(),
    relationships: [{
      target_type: 'agent_run',
      target_id: sourceRunId,
      relation_type: 'derived_from',
      description: 'Архитектурный анализ',
    }],
  };
}

function provenance(decision) {
  return {
    decision,
    provenance_complete: true,
    relationships: decision.relationships.map((relationship) => ({
      id: crypto.randomUUID(),
      source_type: 'decision',
      source_id: decision.id,
      ...relationship,
      description: relationship.description ?? null,
      created_by_user_id: mockUserId,
      created_at: decision.created_at,
    })),
    related_memory_objects: [{
      id: sourceMemoryId,
      type: 'document',
      title: 'Архитектура контекстного контура',
      current_version_id: sourceVersionId,
      sensitivity_level: 'internal',
    }],
    agent_runs: [{
      id: sourceRunId,
      task_id: '70000000-0000-4000-8000-000000000005',
      agent_type: 'architect',
      provider: 'internal-fixture',
      model: null,
      status: 'completed',
      deployment_class: 'internal',
      context_set_hash: `sha256:${'b'.repeat(64)}`,
      result_memory_object_id: '70000000-0000-4000-8000-000000000006',
      requested_by_user_id: mockUserId,
      origin_request_id: '70000000-0000-4000-8000-000000000007',
      created_at: new Date(now - 7_200_000).toISOString(),
      dispatched_at: new Date(now - 7_000_000).toISOString(),
      started_at: new Date(now - 6_900_000).toISOString(),
      finished_at: new Date(now - 6_600_000).toISOString(),
    }],
    source_versions: [{
      agent_run_id: sourceRunId,
      position: 1,
      memory_object_id: sourceMemoryId,
      memory_object_title: 'Архитектура контекстного контура',
      document_version_id: sourceVersionId,
      version_number: 3,
      file_name: 'context-architecture.md',
      file_type: 'text/markdown',
      content_hash: `sha256:${'c'.repeat(64)}`,
      size_bytes: 18420,
      access_reason: 'Основной архитектурный источник',
      frozen_sensitivity_level: 'internal',
      current_sensitivity_level: 'internal',
    }],
    audit_events: [{
      id: '70000000-0000-4000-8000-000000000008',
      actor_type: 'user',
      actor_id: mockUserId,
      action: 'decision.created',
      target_type: 'decision',
      target_id: decision.id,
      request_id: '70000000-0000-4000-8000-000000000009',
      created_at: decision.created_at,
    }],
  };
}
