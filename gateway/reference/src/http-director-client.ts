import { Value } from '@sinclair/typebox/value';
import type { Dispatcher } from 'undici';

import { DirectorClientError, GatewayProtocolError } from './errors.js';
import type { DirectorClient } from './ports.js';
import {
  ContextBundleSchema,
  type ContextBundle,
  type ContextBundleRedeemRequest,
  type GatewayEvent,
} from './protocol.js';

export type ServiceTokenProvider = () => Promise<string> | string;
type DispatcherRequestInit = Omit<RequestInit, 'dispatcher'> & {
  dispatcher?: Dispatcher;
};
type DispatcherFetch = (
  input: Parameters<typeof fetch>[0],
  init?: DispatcherRequestInit,
) => ReturnType<typeof fetch>;
const dispatcherFetch: DispatcherFetch = (input, init) =>
  globalThis.fetch(input, init as unknown as RequestInit);

export interface HttpDirectorClientOptions {
  baseUrl: string;
  tokenProvider: ServiceTokenProvider;
  fetch?: typeof fetch;
  dispatcher?: Dispatcher;
  timeoutMs?: number;
  allowHttpForDevelopment?: boolean;
}

export class HttpDirectorClient implements DirectorClient {
  private readonly baseUrl: URL;
  private readonly tokenProvider: ServiceTokenProvider;
  private readonly fetch: typeof fetch;
  private readonly dispatcher: Dispatcher | undefined;
  private readonly timeoutMs: number;

  constructor(options: HttpDirectorClientOptions) {
    this.baseUrl = new URL(options.baseUrl.endsWith('/') ? options.baseUrl : `${options.baseUrl}/`);
    if (
      this.baseUrl.username.length > 0 ||
      this.baseUrl.password.length > 0 ||
      this.baseUrl.search.length > 0 ||
      this.baseUrl.hash.length > 0
    ) {
      throw new Error('Director base URL must not contain credentials, query, or fragment.');
    }
    if (
      this.baseUrl.protocol !== 'https:' &&
      !(options.allowHttpForDevelopment ?? false)
    ) {
      throw new Error('Director base URL must use HTTPS.');
    }
    if (
      this.baseUrl.protocol === 'https:' &&
      !(options.allowHttpForDevelopment ?? false) &&
      options.dispatcher === undefined &&
      options.fetch === undefined
    ) {
      throw new Error('Director HTTPS transport requires a mutual TLS dispatcher.');
    }
    this.tokenProvider = options.tokenProvider;
    this.fetch = options.fetch ?? globalThis.fetch;
    this.dispatcher = options.dispatcher;
    this.timeoutMs = options.timeoutMs ?? 10_000;
  }

  async redeemContextBundle(
    agentRunId: string,
    capability: string,
    request: ContextBundleRedeemRequest,
    requestId: string,
  ): Promise<ContextBundle> {
    const response = await this.request(
      `internal/v1/agent-runs/${encodeURIComponent(agentRunId)}/context-bundle:redeem`,
      request,
      requestId,
      capability,
    );
    if (response.status !== 200) {
      throw this.redeemError(response.status);
    }

    let payload: unknown;
    try {
      payload = await response.json();
    } catch {
      throw new GatewayProtocolError(
        422,
        'context_hash_mismatch',
        'Director returned an invalid context bundle.',
      );
    }
    if (!Value.Check(ContextBundleSchema, payload)) {
      throw new GatewayProtocolError(
        422,
        'context_hash_mismatch',
        'Director returned an invalid context bundle.',
      );
    }
    return payload;
  }

  async recordEvent(agentRunId: string, event: GatewayEvent, requestId: string): Promise<void> {
    const response = await this.request(
      `internal/v1/agent-runs/${encodeURIComponent(agentRunId)}/events`,
      event,
      requestId,
    );
    if (response.status !== 204) {
      throw new DirectorClientError(
        'Director did not acknowledge the gateway event.',
        response.status,
        response.status === 429 || response.status >= 500,
        retryAfterSeconds(response.headers),
      );
    }
  }

  private async request(
    path: string,
    body: unknown,
    requestId: string,
    capability?: string,
  ): Promise<Response> {
    const token = await this.tokenProvider();
    if (token.length === 0) {
      throw new DirectorClientError('Gateway service token provider returned an empty token.');
    }
    const headers: Record<string, string> = {
      authorization: `Bearer ${token}`,
      'content-type': 'application/json',
      'x-request-id': requestId,
    };
    if (capability !== undefined) {
      headers['x-agent-capability'] = capability;
    }

    try {
      const url = new URL(path, this.baseUrl);
      const request: RequestInit = {
        method: 'POST',
        headers,
        body: JSON.stringify(body),
        redirect: 'error',
        signal: AbortSignal.timeout(this.timeoutMs),
      };
      return this.dispatcher === undefined
        ? await this.fetch(url, request)
        : await dispatcherFetch(url, { ...request, dispatcher: this.dispatcher });
    } catch (error) {
      if (error instanceof DirectorClientError) {
        throw error;
      }
      throw new DirectorClientError('Director request failed.', undefined, true);
    }
  }

  private redeemError(status: number): GatewayProtocolError {
    switch (status) {
      case 400:
        return new GatewayProtocolError(400, 'validation_error', 'Director rejected context redeem.');
      case 401:
        return new GatewayProtocolError(
          401,
          'unauthorized_service',
          'Director rejected gateway authentication.',
        );
      case 403:
        return new GatewayProtocolError(403, 'capability_invalid', 'Capability is invalid.');
      case 404:
        return new GatewayProtocolError(404, 'not_found', 'Context bundle was not found.');
      case 409:
        return new GatewayProtocolError(409, 'capability_used', 'Capability was already used.');
      case 410:
        return new GatewayProtocolError(410, 'capability_expired', 'Capability has expired.');
      case 413:
        return new GatewayProtocolError(413, 'payload_too_large', 'Context bundle is too large.');
      default:
        return new GatewayProtocolError(
          503,
          'unavailable',
          'Director context service is unavailable.',
          status === 429 || status >= 500,
        );
    }
  }
}

function retryAfterSeconds(headers: Headers): number | undefined {
  const value = headers.get('retry-after');
  if (value === null || !/^\d+$/.test(value)) {
    return undefined;
  }
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) && parsed >= 1 ? parsed : undefined;
}
