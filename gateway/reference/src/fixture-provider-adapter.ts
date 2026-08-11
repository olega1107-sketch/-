import { ProviderAdapterError } from './errors.js';
import type {
  ProviderAdapter,
  ProviderInvocation,
  ProviderResult,
} from './ports.js';
import type { AgentExecutionRequest } from './protocol.js';

export type FixtureHandler = (
  invocation: ProviderInvocation,
  signal: AbortSignal,
) => Promise<ProviderResult>;

export class FixtureProviderAdapter implements ProviderAdapter {
  readonly provider = 'fixture';
  readonly adapterVersion = 'fixture/1';
  readonly calls: ProviderInvocation[] = [];

  constructor(private readonly handler?: FixtureHandler) {}

  supports(request: AgentExecutionRequest): boolean {
    return request.provider === this.provider;
  }

  async execute(invocation: ProviderInvocation, signal: AbortSignal): Promise<ProviderResult> {
    this.calls.push(invocation);
    if (signal.aborted) {
      throw new ProviderAdapterError('Fixture request was cancelled.', {
        code: 'provider_timeout',
      });
    }
    if (this.handler !== undefined) {
      return this.handler(invocation, signal);
    }
    return {
      content: `Fixture result for: ${invocation.purpose}`,
      contentType: 'text/markdown',
      finishReason: 'stop',
      providerRequestId: `fixture:${invocation.agentRunId}`,
      usage: { input_tokens: 1, output_tokens: 1 },
    };
  }
}
