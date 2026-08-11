import { createServer } from 'node:http';

const projectId = '10000000-0000-4000-8000-000000000002';
const now = Date.now();

const base = {
  project_id: projectId,
  requested_by_user_id: '10000000-0000-4000-8000-000000000009',
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

const server = createServer((request, response) => {
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
  const decision = url.pathname.match(/^\/api\/v1\/confirmations\/([^/]+):(approve|reject)$/);
  if (request.method === 'POST' && decision !== null) {
    const confirmation = pending.find((item) => item.id === decision[1]);
    if (confirmation === undefined) return json(response, 404, { error: { code: 'not_found' } });
    const action = decision[2];
    pending.splice(pending.indexOf(confirmation), 1);
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

server.listen(8444, '127.0.0.1', () => {
  process.stdout.write('Mock Director API listening at http://127.0.0.1:8444\n');
});

function json(response, status, body) {
  response.statusCode = status;
  response.end(JSON.stringify(body));
}
