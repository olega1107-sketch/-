import { isIP } from 'node:net';

import { Type } from '@sinclair/typebox';
import { Value } from '@sinclair/typebox/value';
import type { Dispatcher } from 'undici';

import { ProviderAdapterError } from './errors.js';
import type {
  ProviderAdapter,
  ProviderInvocation,
  ProviderResult,
} from './ports.js';
import type { AgentExecutionRequest } from './protocol.js';

type DispatcherRequestInit = Omit<RequestInit, 'dispatcher'> & {
  dispatcher?: Dispatcher;
};
type DispatcherFetch = (
  input: Parameters<typeof fetch>[0],
  init?: DispatcherRequestInit,
) => ReturnType<typeof fetch>;

const dispatcherFetch: DispatcherFetch = (input, init) =>
  globalThis.fetch(input, init as unknown as RequestInit);
const modelPattern = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/;
const opaqueIdPattern = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$/;
const hostnamePattern = /^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(?:\.(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?))*$/;

const InternalInferenceResponseSchema = Type.Object(
  {
    protocol_version: Type.Literal('1.0'),
    agent_run_id: Type.String({
      pattern:
        '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-8][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$',
    }),
    model: Type.String({ minLength: 1, maxLength: 128 }),
    provider_request_id: Type.Union([
      Type.Null(),
      Type.String({ minLength: 1, maxLength: 256 }),
    ]),
    content: Type.String(),
    content_type: Type.Union([
      Type.Literal('text/plain'),
      Type.Literal('text/markdown'),
      Type.Literal('application/json'),
    ]),
    finish_reason: Type.Union([
      Type.Literal('stop'),
      Type.Literal('length'),
      Type.Literal('content_filter'),
      Type.Literal('other'),
    ]),
    usage: Type.Optional(
      Type.Object(
        {
          input_tokens: Type.Optional(Type.Integer({ minimum: 0 })),
          output_tokens: Type.Optional(Type.Integer({ minimum: 0 })),
        },
        { additionalProperties: false },
      ),
    ),
    output_summary: Type.Optional(
      Type.Union([Type.Null(), Type.String({ maxLength: 16_384 })]),
    ),
  },
  { additionalProperties: false },
);

export type InternalProviderTokenProvider = () => Promise<string> | string;

export interface InternalInferenceAdapterOptions {
  origin: string;
  models: readonly string[];
  tokenProvider: InternalProviderTokenProvider;
  fetch?: typeof fetch;
  dispatcher?: Dispatcher;
  allowHttpForDevelopment?: boolean;
  maxResponseBytes?: number;
}

export class InternalInferenceAdapter implements ProviderAdapter {
  readonly provider = 'internal';
  readonly adapterVersion = 'internal-http/1';

  private readonly origin: URL;
  private readonly models: ReadonlySet<string>;
  private readonly tokenProvider: InternalProviderTokenProvider;
  private readonly fetch: typeof fetch;
  private readonly dispatcher: Dispatcher | undefined;
  private readonly maxResponseBytes: number;

  constructor(options: InternalInferenceAdapterOptions) {
    this.origin = exactOrigin(options.origin, options.allowHttpForDevelopment ?? false);
    this.models = validatedModels(options.models);
    this.tokenProvider = options.tokenProvider;
    this.fetch = options.fetch ?? globalThis.fetch;
    this.dispatcher = options.dispatcher;
    if (
      this.origin.protocol === 'https:' &&
      !(options.allowHttpForDevelopment ?? false) &&
      options.dispatcher === undefined &&
      options.fetch === undefined
    ) {
      throw new Error('Internal provider HTTPS transport requires a mutual TLS dispatcher.');
    }
    this.maxResponseBytes = positiveInteger(
      options.maxResponseBytes ?? 5 * 1024 * 1024,
      'Internal provider response limit',
    );
  }

  supports(request: AgentExecutionRequest): boolean {
    return (
      request.provider === this.provider &&
      request.deployment_class === 'internal' &&
      (request.provider_data_profile_version ?? null) === null &&
      typeof request.model === 'string' &&
      this.models.has(request.model)
    );
  }

  async execute(invocation: ProviderInvocation, signal: AbortSignal): Promise<ProviderResult> {
    const model = invocation.model;
    if (
      invocation.provider !== this.provider ||
      invocation.providerDataProfileVersion !== null ||
      model === null ||
      !this.models.has(model)
    ) {
      throw new ProviderAdapterError('Internal inference route is not approved.', {
        code: 'policy_violation',
        phase: 'admission',
      });
    }
    const token = await this.tokenProvider();
    if (token.length === 0 || token.length > 4096 || /\s/.test(token)) {
      throw new ProviderAdapterError('Internal provider token is invalid.', {
        code: 'internal_error',
        phase: 'admission',
      });
    }

    let response: Response;
    try {
      const request: RequestInit = {
        method: 'POST',
        headers: {
          accept: 'application/json',
          authorization: `Bearer ${token}`,
          'content-type': 'application/json',
          'idempotency-key': invocation.agentRunId,
          'x-request-id': invocation.originRequestId,
        },
        body: JSON.stringify(internalRequest(invocation, model)),
        redirect: 'error',
        signal,
      };
      const url = new URL('/v1/generate', this.origin);
      response =
        this.dispatcher === undefined
          ? await this.fetch(url, request)
          : await dispatcherFetch(url, { ...request, dispatcher: this.dispatcher });
    } catch {
      if (signal.aborted) {
        throw new ProviderAdapterError('Internal provider request timed out.', {
          code: 'provider_timeout',
          retryable: false,
        });
      }
      throw new ProviderAdapterError('Internal provider is unavailable.', {
        code: 'provider_unavailable',
        retryable: true,
      });
    }

    if (response.status !== 200) {
      await response.body?.cancel().catch(() => undefined);
      throw providerStatusError(response);
    }
    const contentType = response.headers.get('content-type');
    if (contentType === null || !contentType.toLowerCase().startsWith('application/json')) {
      throw new ProviderAdapterError('Internal provider returned an invalid content type.', {
        code: 'normalization_failed',
        phase: 'normalization',
      });
    }
    const payload = await boundedJson(response, this.maxResponseBytes);
    if (!Value.Check(InternalInferenceResponseSchema, payload)) {
      throw new ProviderAdapterError('Internal provider returned an invalid response.', {
        code: 'normalization_failed',
        phase: 'normalization',
      });
    }
    if (payload.agent_run_id !== invocation.agentRunId || payload.model !== model) {
      throw new ProviderAdapterError('Internal provider response identity does not match the request.', {
        code: 'normalization_failed',
        phase: 'normalization',
      });
    }
    return {
      content: payload.content,
      contentType: payload.content_type,
      finishReason: payload.finish_reason,
      providerRequestId: payload.provider_request_id,
      ...(payload.usage === undefined ? {} : { usage: payload.usage }),
      ...(payload.output_summary === undefined
        ? {}
        : { outputSummary: payload.output_summary }),
    };
  }
}

function internalRequest(invocation: ProviderInvocation, model: string) {
  return {
    protocol_version: '1.0',
    agent_run_id: invocation.agentRunId,
    project_id: invocation.projectId,
    origin_request_id: invocation.originRequestId,
    agent_type: invocation.agentType,
    model,
    purpose: invocation.purpose,
    instructions: invocation.instructions,
    deadline_at: invocation.deadlineAt,
    context: {
      context_set_hash: invocation.context.context_set_hash,
      max_sensitivity_level: invocation.context.max_sensitivity_level,
      items: invocation.context.items.map((item) => ({
        position: item.position,
        file_name: item.file_name,
        media_type: item.media_type,
        size_bytes: item.size_bytes,
        content_encoding: item.content_encoding,
        content: item.content,
        content_hash: item.content_hash,
        sensitivity_level: item.sensitivity_level,
        access_reason: item.access_reason,
      })),
    },
  };
}

async function boundedJson(response: Response, maximumBytes: number): Promise<unknown> {
  if (response.body === null) {
    throw new ProviderAdapterError('Internal provider returned an empty response.', {
      code: 'normalization_failed',
      phase: 'normalization',
    });
  }
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    for (;;) {
      const chunk = await reader.read();
      if (chunk.done) break;
      size += chunk.value.byteLength;
      if (size > maximumBytes) {
        await reader.cancel();
        throw new ProviderAdapterError('Internal provider response is too large.', {
          code: 'output_too_large',
          phase: 'normalization',
        });
      }
      chunks.push(chunk.value);
    }
  } catch (error) {
    if (error instanceof ProviderAdapterError) throw error;
    throw new ProviderAdapterError('Internal provider response could not be read.', {
      code: 'provider_unavailable',
      retryable: true,
    });
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(Buffer.concat(chunks).toString('utf8')) as unknown;
  } catch {
    throw new ProviderAdapterError('Internal provider returned malformed JSON.', {
      code: 'normalization_failed',
      phase: 'normalization',
    });
  }
  return parsed;
}

function providerStatusError(response: Response): ProviderAdapterError {
  const providerRequestId = opaqueHeader(response.headers, 'x-provider-request-id');
  const common = {
    providerStatus: response.status,
    ...(providerRequestId === undefined ? {} : { providerRequestId }),
  };
  if (response.status === 429) {
    return new ProviderAdapterError('Internal provider rate limit was reached.', {
      code: 'provider_rate_limited',
      retryable: true,
      ...common,
      ...retryAfter(response.headers),
    });
  }
  if (response.status === 408 || response.status === 504) {
    return new ProviderAdapterError('Internal provider request timed out.', {
      code: 'provider_timeout',
      retryable: true,
      ...common,
    });
  }
  if (response.status === 502 || response.status === 503 || response.status >= 500) {
    return new ProviderAdapterError('Internal provider is unavailable.', {
      code: 'provider_unavailable',
      retryable: true,
      ...common,
      ...retryAfter(response.headers),
    });
  }
  return new ProviderAdapterError('Internal provider rejected the request.', {
    code: 'provider_rejected',
    retryable: false,
    ...common,
  });
}

function retryAfter(headers: Headers): { retryAfterSeconds?: number } {
  const value = headers.get('retry-after');
  if (value === null || !/^\d+$/.test(value)) return {};
  const seconds = Number(value);
  return Number.isSafeInteger(seconds) && seconds >= 1
    ? { retryAfterSeconds: seconds }
    : {};
}

function opaqueHeader(headers: Headers, name: string): string | undefined {
  const value = headers.get(name);
  return value !== null && opaqueIdPattern.test(value) ? value : undefined;
}

function exactOrigin(value: string, allowHttpForDevelopment: boolean): URL {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error('Internal provider origin must be an absolute URL.');
  }
  const schemeAllowed =
    url.protocol === 'https:' ||
    (allowHttpForDevelopment && url.protocol === 'http:');
  if (
    !schemeAllowed ||
    url.username.length > 0 ||
    url.password.length > 0 ||
    url.pathname !== '/' ||
    url.search.length > 0 ||
    url.hash.length > 0 ||
    isIP(url.hostname) !== 0 ||
    !hostnamePattern.test(url.hostname)
  ) {
    throw new Error('Internal provider origin must be an exact HTTPS DNS origin.');
  }
  return url;
}

function validatedModels(values: readonly string[]): ReadonlySet<string> {
  if (
    !Array.isArray(values) ||
    values.length === 0 ||
    values.length > 100 ||
    values.some((value) => typeof value !== 'string' || !modelPattern.test(value)) ||
    new Set(values).size !== values.length
  ) {
    throw new Error('Internal provider models must be 1 through 100 unique model identifiers.');
  }
  return new Set(values);
}

function positiveInteger(value: number, name: string): number {
  if (!Number.isSafeInteger(value) || value < 1) {
    throw new Error(`${name} must be a positive integer.`);
  }
  return value;
}
