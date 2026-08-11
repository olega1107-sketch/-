import type { DeploymentClass } from './protocol.js';

export interface AgentRoute {
  provider: string;
  model: string | null;
  deploymentClass: DeploymentClass;
  providerDataProfileVersion: string | null;
}

export interface AgentRouteDefinition extends AgentRoute {
  agentType: string;
}

export interface AgentRouteResolver {
  resolve(agentType: string): Promise<AgentRoute | null> | AgentRoute | null;
}

export interface StaticAgentRouteResolverOptions {
  routes: readonly AgentRouteDefinition[];
  fallback?: AgentRoute;
}

export class StaticAgentRouteResolver implements AgentRouteResolver {
  private readonly routes: ReadonlyMap<string, AgentRoute>;
  private readonly fallback: AgentRoute | null;

  constructor(options: StaticAgentRouteResolverOptions) {
    const routes = new Map<string, AgentRoute>();
    for (const definition of options.routes) {
      const agentType = requiredText(definition.agentType, 'Agent route type');
      if (routes.has(agentType)) {
        throw new Error(`Agent route type ${agentType} is configured more than once.`);
      }
      routes.set(agentType, normalizedRoute(definition));
    }
    this.routes = routes;
    this.fallback = options.fallback === undefined ? null : normalizedRoute(options.fallback);
    if (this.routes.size === 0 && this.fallback === null) {
      throw new Error('At least one agent route or a fallback route is required.');
    }
  }

  resolve(agentType: string): AgentRoute | null {
    return this.routes.get(agentType) ?? this.fallback;
  }
}

function normalizedRoute(route: AgentRoute): AgentRoute {
  const deploymentClass = route.deploymentClass;
  if (deploymentClass !== 'internal' && deploymentClass !== 'external') {
    throw new Error('Agent route deployment class must be internal or external.');
  }
  const profile = nullableText(route.providerDataProfileVersion);
  if (deploymentClass === 'external' && profile === null) {
    throw new Error('External agent route requires a provider data profile version.');
  }
  if (deploymentClass === 'internal' && profile !== null) {
    throw new Error('Internal agent route cannot set a provider data profile version.');
  }
  return Object.freeze({
    provider: requiredText(route.provider, 'Agent route provider'),
    model: nullableText(route.model),
    deploymentClass,
    providerDataProfileVersion: profile,
  });
}

function requiredText(value: string, label: string): string {
  const normalized = value.trim();
  if (normalized.length === 0) {
    throw new Error(`${label} must not be blank.`);
  }
  return normalized;
}

function nullableText(value: string | null): string | null {
  if (value === null) {
    return null;
  }
  const normalized = value.trim();
  return normalized.length === 0 ? null : normalized;
}
