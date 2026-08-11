import { describe, expect, it } from 'vitest';

import { StaticAgentRouteResolver } from '../src/agent-routing.js';

describe('Static agent route resolver', () => {
  it('resolves independent provider profiles by exact agent type', () => {
    const resolver = new StaticAgentRouteResolver({
      routes: [
        {
          agentType: 'architect',
          provider: 'internal-llm',
          model: 'architecture-v2',
          deploymentClass: 'internal',
          providerDataProfileVersion: null,
        },
        {
          agentType: 'researcher',
          provider: 'openai',
          model: 'gpt-5',
          deploymentClass: 'external',
          providerDataProfileVersion: 'openai-enterprise-v1',
        },
      ],
    });

    expect(resolver.resolve('architect')).toEqual({
      provider: 'internal-llm',
      model: 'architecture-v2',
      deploymentClass: 'internal',
      providerDataProfileVersion: null,
    });
    expect(resolver.resolve('researcher')).toMatchObject({
      provider: 'openai',
      deploymentClass: 'external',
    });
    expect(resolver.resolve('unknown')).toBeNull();
    expect(Object.isFrozen(resolver.resolve('architect'))).toBe(true);
  });

  it('supports a development fallback without overriding exact routes', () => {
    const resolver = new StaticAgentRouteResolver({
      routes: [
        {
          agentType: 'architect',
          provider: 'specialized',
          model: null,
          deploymentClass: 'internal',
          providerDataProfileVersion: null,
        },
      ],
      fallback: {
        provider: 'fixture',
        model: null,
        deploymentClass: 'internal',
        providerDataProfileVersion: null,
      },
    });

    expect(resolver.resolve('architect')?.provider).toBe('specialized');
    expect(resolver.resolve('other')?.provider).toBe('fixture');
  });

  it('rejects duplicates and invalid deployment/profile combinations', () => {
    expect(
      () =>
        new StaticAgentRouteResolver({
          routes: [internalRoute('architect'), internalRoute(' architect ')],
        }),
    ).toThrow(/configured more than once/);
    expect(
      () =>
        new StaticAgentRouteResolver({
          routes: [
            {
              ...internalRoute('researcher'),
              deploymentClass: 'external',
            },
          ],
        }),
    ).toThrow(/requires a provider data profile/);
    expect(
      () =>
        new StaticAgentRouteResolver({
          routes: [
            {
              ...internalRoute('architect'),
              providerDataProfileVersion: 'external-profile',
            },
          ],
        }),
    ).toThrow(/cannot set a provider data profile/);
  });
});

function internalRoute(agentType: string) {
  return {
    agentType,
    provider: 'fixture',
    model: null,
    deploymentClass: 'internal' as const,
    providerDataProfileVersion: null,
  };
}
