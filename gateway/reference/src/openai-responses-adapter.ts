import OpenAI, {
  APIConnectionError,
  APIConnectionTimeoutError,
  APIError,
} from 'openai';
import type {
  Response,
  ResponseCreateParamsNonStreaming,
  ResponseInputContent,
} from 'openai/resources/responses/responses';

import { ProviderAdapterError } from './errors.js';
import type {
  ProviderAdapter,
  ProviderInvocation,
  ProviderResult,
} from './ports.js';
import type { AgentExecutionRequest, FinishReason } from './protocol.js';

export interface OpenAIResponsesPort {
  create(
    body: ResponseCreateParamsNonStreaming,
    options?: { signal?: AbortSignal },
  ): Promise<Response>;
}

export interface OpenAIResponsesAdapterOptions {
  apiKey?: string;
  responses?: OpenAIResponsesPort;
}

export class OpenAIResponsesAdapter implements ProviderAdapter {
  readonly provider = 'openai';
  readonly adapterVersion = 'openai-responses/1';
  private readonly responses: OpenAIResponsesPort;

  constructor(options: OpenAIResponsesAdapterOptions) {
    if (options.responses !== undefined) {
      this.responses = options.responses;
      return;
    }
    if ((options.apiKey ?? '').length === 0) {
      throw new Error('OpenAI API key is required when no Responses client is injected.');
    }
    this.responses = new OpenAI({ apiKey: options.apiKey }).responses;
  }

  supports(request: AgentExecutionRequest): boolean {
    return (
      request.provider === this.provider &&
      request.deployment_class === 'external' &&
      typeof request.provider_data_profile_version === 'string' &&
      request.provider_data_profile_version.length > 0 &&
      request.model !== undefined &&
      request.model !== null &&
      request.model.length > 0
    );
  }

  async execute(invocation: ProviderInvocation, signal: AbortSignal): Promise<ProviderResult> {
    if (
      invocation.provider !== this.provider ||
      invocation.providerDataProfileVersion === null ||
      invocation.model === null ||
      invocation.model.length === 0
    ) {
      throw new ProviderAdapterError('OpenAI execution requires an approved external route.', {
        code: 'policy_violation',
        phase: 'admission',
      });
    }

    let response: Response;
    try {
      response = await this.responses.create(
        {
          model: invocation.model,
          instructions: invocation.instructions,
          input: [
            {
              role: 'user',
              content: this.buildInput(invocation),
            },
          ],
          store: false,
          tools: [],
        },
        { signal },
      );
    } catch (error) {
      throw this.mapError(error);
    }

    if (response.error !== null) {
      throw new ProviderAdapterError('OpenAI rejected the response request.', {
        code: 'provider_rejected',
        providerRequestId: response.id,
      });
    }
    if (response.output.some((item) => item.type !== 'message' && item.type !== 'reasoning')) {
      throw new ProviderAdapterError('Provider returned an unsupported tool call.', {
        code: 'unsupported_tool_call',
        providerRequestId: response.id,
      });
    }
    if (
      response.output.some(
        (item) => item.type === 'message' && item.content.some((part) => part.type === 'refusal'),
      )
    ) {
      throw new ProviderAdapterError('OpenAI refused the request.', {
        code: 'provider_rejected',
        providerRequestId: response.id,
      });
    }

    return {
      content: response.output_text,
      contentType: 'text/markdown',
      finishReason: finishReason(response),
      providerRequestId: response.id,
      ...(response.usage === undefined
        ? {}
        : {
            usage: {
              input_tokens: response.usage.input_tokens,
              output_tokens: response.usage.output_tokens,
            },
          }),
    };
  }

  private buildInput(invocation: ProviderInvocation): ResponseInputContent[] {
    const content: ResponseInputContent[] = [
      {
        type: 'input_text',
        text: `Purpose:\n${invocation.purpose}\n\nFrozen context follows in declared order.`,
      },
    ];
    for (const item of invocation.context.items) {
      const label = [
        `Context item ${item.position}`,
        `File: ${item.file_name}`,
        `Media type: ${item.media_type}`,
        `Access reason: ${item.access_reason}`,
      ].join('\n');
      if (item.content_encoding === 'utf-8') {
        content.push({ type: 'input_text', text: `${label}\n\n${item.content}` });
      } else {
        content.push({ type: 'input_text', text: label });
        content.push({
          type: 'input_file',
          filename: item.file_name,
          file_data: `data:${item.media_type};base64,${item.content}`,
        });
      }
    }
    return content;
  }

  private mapError(error: unknown): ProviderAdapterError {
    if (error instanceof APIConnectionTimeoutError) {
      return new ProviderAdapterError('OpenAI request timed out.', {
        code: 'provider_timeout',
        retryable: false,
      });
    }
    if (error instanceof APIConnectionError) {
      return new ProviderAdapterError('OpenAI is unavailable.', {
        code: 'provider_unavailable',
        retryable: true,
      });
    }
    if (error instanceof APIError) {
      const status = error.status;
      const common = {
        ...(status === undefined ? {} : { providerStatus: status }),
        ...(error.requestID === undefined || error.requestID === null
          ? {}
          : { providerRequestId: error.requestID }),
      };
      if (status === 429) {
        return new ProviderAdapterError('OpenAI rate limit was reached.', {
          code: 'provider_rate_limited',
          retryable: true,
          ...common,
          ...retryAfter(error.headers),
        });
      }
      if (status !== undefined && status >= 500) {
        return new ProviderAdapterError('OpenAI is unavailable.', {
          code: 'provider_unavailable',
          retryable: true,
          ...common,
        });
      }
      return new ProviderAdapterError('OpenAI rejected the request.', {
        code: 'provider_rejected',
        retryable: false,
        ...common,
      });
    }
    return new ProviderAdapterError('OpenAI adapter failed.', {
      code: 'internal_error',
      retryable: false,
    });
  }
}

function finishReason(response: Response): FinishReason {
  switch (response.incomplete_details?.reason) {
    case 'max_output_tokens':
      return 'length';
    case 'content_filter':
      return 'content_filter';
    default:
      return 'stop';
  }
}

function retryAfter(headers: Headers | undefined): { retryAfterSeconds?: number } {
  const value = headers?.get('retry-after');
  if (value === undefined || value === null || !/^\d+$/.test(value)) {
    return {};
  }
  const seconds = Number(value);
  return Number.isSafeInteger(seconds) && seconds >= 1 ? { retryAfterSeconds: seconds } : {};
}
