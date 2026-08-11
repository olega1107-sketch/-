import { Value } from '@sinclair/typebox/value';
import type { Dispatcher } from 'undici';

import { DirectorProtocolError } from './errors.js';
import { AgentExecutionReceiptSchema } from './protocol.js';
import type { AgentGatewayClient, AgentGatewayDispatch } from './task-ports.js';

export type GatewayServiceTokenProvider = () => Promise<string> | string;
type DispatcherRequestInit = Omit<RequestInit, 'dispatcher'> & {
  dispatcher?: Dispatcher;
};
type DispatcherFetch = (
  input: Parameters<typeof fetch>[0],
  init?: DispatcherRequestInit,
) => ReturnType<typeof fetch>;
const dispatcherFetch: DispatcherFetch = (input, init) =>
  globalThis.fetch(input, init as unknown as RequestInit);

export interface HttpAgentGatewayClientOptions {
  baseUrl: string;
  tokenProvider: GatewayServiceTokenProvider;
  fetch?: typeof fetch;
  dispatcher?: Dispatcher;
  timeoutMs?: number;
  allowHttpForDevelopment?: boolean;
}

export class HttpAgentGatewayClient implements AgentGatewayClient {
  private readonly baseUrl: URL;
  private readonly tokenProvider: GatewayServiceTokenProvider;
  private readonly fetch: typeof fetch;
  private readonly dispatcher: Dispatcher | undefined;
  private readonly timeoutMs: number;

  constructor(options: HttpAgentGatewayClientOptions) {
    this.baseUrl = new URL(options.baseUrl.endsWith('/') ? options.baseUrl : `${options.baseUrl}/`);
    if (
      this.baseUrl.username.length > 0 ||
      this.baseUrl.password.length > 0 ||
      this.baseUrl.search.length > 0 ||
      this.baseUrl.hash.length > 0
    ) {
      throw new Error('Agent Gateway base URL must not contain credentials, query, or fragment.');
    }
    if (this.baseUrl.protocol !== 'https:' && !(options.allowHttpForDevelopment ?? false)) {
      throw new Error('Agent Gateway base URL must use HTTPS.');
    }
    if (
      this.baseUrl.protocol === 'https:' &&
      !(options.allowHttpForDevelopment ?? false) &&
      options.dispatcher === undefined &&
      options.fetch === undefined
    ) {
      throw new Error('Agent Gateway HTTPS transport requires a mutual TLS dispatcher.');
    }
    this.tokenProvider = options.tokenProvider;
    this.fetch = options.fetch ?? globalThis.fetch;
    this.dispatcher = options.dispatcher;
    this.timeoutMs = options.timeoutMs ?? 10_000;
  }

  async dispatch(input: AgentGatewayDispatch): Promise<void> {
    const token = await this.tokenProvider();
    if (token.length === 0) {
      throw internalGatewayError();
    }

    let response: Response;
    try {
      const url = new URL(
        `internal/v1/agent-runs/${encodeURIComponent(input.agentRunId)}:execute`,
        this.baseUrl,
      );
      const request: RequestInit = {
        method: 'POST',
        headers: {
          authorization: `Bearer ${token}`,
          'content-type': 'application/json',
          'idempotency-key': input.agentRunId,
          'x-agent-capability': input.capability,
          'x-request-id': input.requestId,
        },
        body: JSON.stringify(input.request),
        redirect: 'error',
        signal: AbortSignal.timeout(this.timeoutMs),
      };
      response =
        this.dispatcher === undefined
          ? await this.fetch(url, request)
          : await dispatcherFetch(url, { ...request, dispatcher: this.dispatcher });
    } catch {
      throw internalGatewayError();
    }

    if (response.status === 429) {
      throw new DirectorProtocolError(
        429,
        'rate_limited',
        'Agent Gateway admission is rate limited.',
        true,
        retryAfterDetails(response.headers),
      );
    }
    if (response.status === 409) {
      throw new DirectorProtocolError(
        409,
        'conflict',
        'Agent Gateway rejected the idempotent dispatch.',
      );
    }
    if (response.status !== 202) {
      throw internalGatewayError();
    }

    let payload: unknown;
    try {
      payload = await response.json();
    } catch {
      throw internalGatewayError();
    }
    if (
      !Value.Check(AgentExecutionReceiptSchema, payload) ||
      payload.agent_run_id !== input.agentRunId ||
      payload.request_fingerprint !== input.request.request_fingerprint
    ) {
      throw internalGatewayError();
    }
  }
}

function internalGatewayError(): DirectorProtocolError {
  return new DirectorProtocolError(
    500,
    'internal_error',
    'Agent Gateway did not accept the frozen run.',
    true,
  );
}

function retryAfterDetails(headers: Headers): Readonly<Record<string, unknown>> {
  const value = headers.get('retry-after');
  if (value === null || !/^\d+$/.test(value)) {
    return {};
  }
  const seconds = Number(value);
  return Number.isSafeInteger(seconds) && seconds >= 1
    ? { retry_after_seconds: seconds }
    : {};
}
