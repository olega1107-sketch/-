const base = process.env.DIRECTOR_SMOKE_BASE_URL ?? 'http://127.0.0.1:8444/api/v1';
const projectId = '10000000-0000-4000-8000-000000000002';

async function request(path, options = {}) {
  const headers = new Headers(options.headers);
  headers.set('x-request-id', crypto.randomUUID());
  const response = await fetch(`${base}${path}`, { ...options, headers });
  const payload = await response.json();
  if (!response.ok) throw new Error(`${options.method ?? 'GET'} ${path}: ${response.status}`);
  return payload;
}

const upload = new FormData();
upload.set('project_id', projectId);
upload.set('title', 'Synthetic workflow document');
upload.set('type', 'document');
upload.set('sensitivity_level', 'internal');
upload.set('file', new Blob(['Synthetic pilot data.'], { type: 'text/plain' }), 'workflow.txt');
const memory = await request('/memory-objects:upload', { method: 'POST', body: upload });

const task = await request('/tasks', {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ project_id: projectId, title: 'Synthetic workflow task', user_request: 'Summarize the selected document.' }),
});
const match = await request(`/tasks/${task.id}/context:search`, {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ query: task.user_request, limit: 20 }),
});
const candidate = match.candidates.find((item) => item.memory_object_id === memory.id);
if (candidate === undefined) throw new Error('Uploaded document was not returned as a context candidate.');
const detail = await request(`/memory-objects/${memory.id}`);
if (detail.current_version === null) throw new Error('Current document version is unavailable.');
const run = await request(`/tasks/${task.id}/agent-runs`, {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify({
    agent_type: 'architect', purpose: task.title, instructions: 'Return a concise summary.',
    context: [{ memory_object_id: detail.id, document_version_id: detail.current_version.id, access_reason: task.user_request }],
  }),
});
if (run.status !== 'awaiting_user_confirmation' && run.status !== 'queued') throw new Error(`Unexpected agent run status: ${run.status}`);
console.log('workflow-smoke=PASS');
