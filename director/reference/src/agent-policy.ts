import { sensitivityRank } from './canonical.js';
import { DirectorProtocolError } from './errors.js';
import type { DeploymentClass, SensitivityLevel } from './protocol.js';
import type { ConfirmationOperation } from './confirmation-protocol.js';

export interface ProjectAiPolicy {
  externalAiEnabled: boolean;
  allowedProviderIds: readonly string[];
  profileVersions: Readonly<Record<string, unknown>>;
  maxExternalSensitivity: SensitivityLevel;
  confirmInternalExternalShare: boolean;
  bulkContextObjectLimit: number;
}

export type AgentConfirmationReason =
  | 'bulk_context_share'
  | 'internal_external_share'
  | 'confidential_external_share';

export interface AgentPolicyDecision {
  confirmationReasons: readonly AgentConfirmationReason[];
  confirmationOperation: ConfirmationOperation | null;
}

export interface AgentPolicyRequest {
  deploymentClass: DeploymentClass;
  provider: string;
  providerDataProfileVersion: string | null;
  maximumContextSensitivity: SensitivityLevel;
  contextItemCount: number;
}

export function evaluateAgentPolicy(
  policy: ProjectAiPolicy,
  request: AgentPolicyRequest,
): AgentPolicyDecision {
  const reasons: AgentConfirmationReason[] = [];

  if (request.deploymentClass === 'external') {
    requireExternalPolicy(policy, request);
    if (request.maximumContextSensitivity === 'confidential') {
      reasons.push('confidential_external_share');
    } else if (
      request.maximumContextSensitivity === 'internal' &&
      policy.confirmInternalExternalShare
    ) {
      reasons.push('internal_external_share');
    }
  }

  if (request.contextItemCount > policy.bulkContextObjectLimit) {
    reasons.push('bulk_context_share');
  }

  return {
    confirmationReasons: reasons,
    confirmationOperation:
      reasons.length === 0
        ? null
        : reasons.includes('bulk_context_share')
          ? 'bulk_context_share'
          : 'agent_context_share',
  };
}

function requireExternalPolicy(
  policy: ProjectAiPolicy,
  request: AgentPolicyRequest,
): void {
  if (!policy.externalAiEnabled) {
    throw policyDenied('external_ai_disabled');
  }
  if (!policy.allowedProviderIds.includes(request.provider)) {
    throw policyDenied('provider_not_allowed');
  }
  if (
    request.providerDataProfileVersion === null ||
    policy.profileVersions[request.provider] !== request.providerDataProfileVersion
  ) {
    throw policyDenied('provider_profile_not_allowed');
  }
  if (request.maximumContextSensitivity === 'restricted') {
    throw policyDenied('restricted_external_share_forbidden');
  }
  if (
    sensitivityRank(request.maximumContextSensitivity) >
    sensitivityRank(policy.maxExternalSensitivity)
  ) {
    throw policyDenied('sensitivity_not_allowed');
  }
}

function policyDenied(reasonCode: string): DirectorProtocolError {
  return new DirectorProtocolError(
    403,
    'access_denied',
    'Project AI policy does not allow this agent execution.',
    false,
    { reason_codes: [reasonCode] },
  );
}
