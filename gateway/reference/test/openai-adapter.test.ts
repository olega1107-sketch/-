import type {
  Response,
  ResponseCreateParamsNonStreaming,
} from 'openai/resources/responses/responses';
import { describe, expect, it } from 'vitest';

import {
  OpenAIResponsesAdapter,
  type OpenAIResponsesPort,
} from '../src/openai-responses-adapter.js';
import type { ProviderInvocation } from '../src/ports.js';
import { executionFixture } from './helpers.js';

class CapturingResponses implements OpenAIResponsesPort {
  body?: ResponseCreateParamsNonStreaming;

  constructor(private readonly response: Response) {}

  async create(body: ResponseCreateParamsNonStreaming): Promise<Response> {
    this.body = body;
    return this.response;
  }
}

describe('OpenAIResponsesAdapter', () => {
  it('uses stateless Responses input and preserves binary context as a data URI', async () => {
    const fixture = openAiFixture();
    const binary = Buffer.from('binary-payload', 'utf8');
    fixture.bundle.items.push({
      ...fixture.bundle.items[0]!,
      position: 2,
      document_version_id: '10000000-0000-4000-8000-000000000008',
      file_name: 'evidence.pdf',
      media_type: 'application/pdf',
      size_bytes: binary.byteLength,
      content_encoding: 'base64',
      content: binary.toString('base64'),
    });
    const responses = new CapturingResponses(responseFixture());
    const adapter = new OpenAIResponsesAdapter({ responses });

    const result = await adapter.execute(invocation(fixture), new AbortController().signal);

    expect(result).toMatchObject({
      content: 'Final answer',
      finishReason: 'stop',
      providerRequestId: 'resp_123',
      usage: { input_tokens: 12, output_tokens: 5 },
    });
    expect(responses.body).toMatchObject({
      model: 'gpt-test',
      instructions: fixture.request.instructions,
      store: false,
      tools: [],
      input: [
        {
          role: 'user',
          content: expect.arrayContaining([
            expect.objectContaining({ type: 'input_text', text: expect.stringContaining('Purpose:') }),
            expect.objectContaining({
              type: 'input_file',
              filename: 'evidence.pdf',
              file_data: `data:application/pdf;base64,${binary.toString('base64')}`,
            }),
          ]),
        },
      ],
    });
  });

  it('rejects any tool output even though no tools were offered', async () => {
    const fixture = openAiFixture();
    const toolResponse = responseFixture({
      output: [{ type: 'function_call' }],
      output_text: '',
    });
    const adapter = new OpenAIResponsesAdapter({
      responses: new CapturingResponses(toolResponse),
    });

    await expect(
      adapter.execute(invocation(fixture), new AbortController().signal),
    ).rejects.toMatchObject({
      code: 'unsupported_tool_call',
    });
  });

  it('maps provider refusal to a failed run instead of an empty success', async () => {
    const fixture = openAiFixture();
    const refusal = responseFixture({
      output_text: '',
      output: [
        {
          id: 'msg_refusal',
          type: 'message',
          role: 'assistant',
          status: 'completed',
          content: [{ type: 'refusal', refusal: 'Cannot comply.' }],
        },
      ],
    });
    const adapter = new OpenAIResponsesAdapter({
      responses: new CapturingResponses(refusal),
    });

    await expect(
      adapter.execute(invocation(fixture), new AbortController().signal),
    ).rejects.toMatchObject({ code: 'provider_rejected' });
  });

  it('cannot be selected for an internal or unprofiled route', async () => {
    const fixture = executionFixture({ provider: 'openai', model: 'gpt-test' });
    const adapter = new OpenAIResponsesAdapter({
      responses: new CapturingResponses(responseFixture()),
    });

    expect(adapter.supports(fixture.request)).toBe(false);
    await expect(
      adapter.execute(invocation(fixture), new AbortController().signal),
    ).rejects.toMatchObject({ code: 'policy_violation', phase: 'admission' });
  });
});

function openAiFixture() {
  return executionFixture({
    provider: 'openai',
    model: 'gpt-test',
    deploymentClass: 'external',
    providerDataProfileVersion: 'approved-profile-v1',
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

function responseFixture(overrides: Record<string, unknown> = {}): Response {
  return {
    id: 'resp_123',
    output_text: 'Final answer',
    output: [
      {
        id: 'msg_123',
        type: 'message',
        role: 'assistant',
        status: 'completed',
        content: [{ type: 'output_text', text: 'Final answer', annotations: [] }],
      },
    ],
    error: null,
    incomplete_details: null,
    usage: { input_tokens: 12, output_tokens: 5 },
    ...overrides,
  } as unknown as Response;
}
