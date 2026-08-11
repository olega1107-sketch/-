import type { FailurePhase, GatewayFailureCode } from './protocol.js';

export class GatewayProtocolError extends Error {
  constructor(
    readonly statusCode: number,
    readonly code: string,
    message: string,
    readonly retryable = false,
    readonly details: Readonly<Record<string, unknown>> = {},
  ) {
    super(message);
    this.name = 'GatewayProtocolError';
  }
}

export class DirectorClientError extends Error {
  constructor(
    message: string,
    readonly statusCode?: number,
    readonly retryable = false,
    readonly retryAfterSeconds?: number,
  ) {
    super(message);
    this.name = 'DirectorClientError';
  }
}

export interface ProviderAdapterErrorOptions {
  code: GatewayFailureCode;
  phase?: FailurePhase;
  retryable?: boolean;
  providerStatus?: number;
  retryAfterSeconds?: number;
  providerRequestId?: string;
}

export class ProviderAdapterError extends Error {
  readonly code: GatewayFailureCode;
  readonly phase: FailurePhase;
  readonly retryable: boolean;
  readonly providerStatus: number | undefined;
  readonly retryAfterSeconds: number | undefined;
  readonly providerRequestId: string | undefined;

  constructor(message: string, options: ProviderAdapterErrorOptions) {
    super(message);
    this.name = 'ProviderAdapterError';
    this.code = options.code;
    this.phase = options.phase ?? 'provider';
    this.retryable = options.retryable ?? false;
    this.providerStatus = options.providerStatus;
    this.retryAfterSeconds = options.retryAfterSeconds;
    this.providerRequestId = options.providerRequestId;
  }
}
