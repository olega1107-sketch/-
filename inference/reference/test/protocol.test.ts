import assert from 'node:assert/strict';
import test from 'node:test';

import { parseInferenceRequest, ProtocolError } from '../src/protocol.js';
import { buildPrompt, LlamaClient } from '../src/upstream.js';

const model = 'Qwen3-4B-Q4_K_M';

test('accepts the exact gateway protocol and preserves ordered context', () => {
  const parsed = parseInferenceRequest(requestFixture(), model);
  assert.equal(parsed.model, model);
  assert.equal(parsed.context.items[0]?.position, 0);
  assert.match(buildPrompt(parsed), /approved\.md/);
});

test('rejects unknown fields and non-approved models', () => {
  assert.throws(
    () => parseInferenceRequest({ ...requestFixture(), extra: true }, model),
    ProtocolError,
  );
  assert.throws(
    () => parseInferenceRequest({ ...requestFixture(), model: 'other-model' }, model),
    /not approved/,
  );
});

test('maps a llama.cpp chat completion to the internal provider result', async () => {
  let upstreamBody: Record<string, unknown> | undefined;
  const client = new LlamaClient({
    origin: 'http://127.0.0.1:8080',
    model,
    maxPromptCharacters: 48_000,
    maxOutputTokens: 1024,
    timeoutMs: 5000,
    fetch: async (_input, init) => {
      upstreamBody = JSON.parse(String(init?.body)) as Record<string, unknown>;
      return Response.json({
        id: 'completion-01',
        choices: [{ message: { content: '<think>private</think>Approved answer.' }, finish_reason: 'stop' }],
        usage: { prompt_tokens: 10, completion_tokens: 3 },
      });
    },
  });
  const result = await client.generate(parseInferenceRequest(requestFixture(), model), new AbortController().signal);
  assert.equal(result.content, 'Approved answer.');
  assert.equal(result.finishReason, 'stop');
  assert.deepEqual(result.usage, { input_tokens: 10, output_tokens: 3 });
  assert.equal(upstreamBody?.model, model);
  assert.equal(upstreamBody?.stream, false);
});

test('fails closed when approved context exceeds the configured prompt limit', async () => {
  const client = new LlamaClient({
    origin: 'http://127.0.0.1:8080',
    model,
    maxPromptCharacters: 8,
    maxOutputTokens: 64,
    timeoutMs: 5000,
    fetch: async () => { throw new Error('must not be called'); },
  });
  await assert.rejects(
    client.generate(parseInferenceRequest(requestFixture(), model), new AbortController().signal),
    /prompt limit/,
  );
});

function requestFixture(): Record<string, unknown> {
  return {
    protocol_version: '1.0',
    agent_run_id: '11111111-1111-4111-8111-111111111111',
    project_id: '22222222-2222-4222-8222-222222222222',
    origin_request_id: 'request-01',
    agent_type: 'architect_internal',
    model,
    purpose: 'Review the approved architecture note.',
    instructions: 'Summarize the decision.',
    deadline_at: new Date(Date.now() + 60_000).toISOString(),
    context: {
      context_set_hash: 'a'.repeat(64),
      max_sensitivity_level: 'internal',
      items: [{
        position: 0,
        file_name: 'approved.md',
        media_type: 'text/markdown',
        size_bytes: 12,
        content_encoding: 'utf-8',
        content: 'Approved data',
        content_hash: 'b'.repeat(64),
        sensitivity_level: 'internal',
        access_reason: 'Project membership verified by Director.',
      }],
    },
  };
}
