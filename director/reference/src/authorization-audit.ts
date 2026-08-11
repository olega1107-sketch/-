import { DirectorProtocolError } from './errors.js';

export interface AuthorizationAttempt {
  actorUserId: string;
  principalUserId?: string;
  action: string;
  resourceType: string;
  resourceId: string | null;
  projectId: string | null;
  requestId: string;
}

export interface AuthorizationDenial {
  actorUserId: string;
  principalUserId: string;
  action: string;
  resourceType: string;
  resourceId: string | null;
  projectId: string | null;
  requestId: string;
  reasonCodes: readonly string[];
  missingPermissions: readonly string[];
  responseConcealed: boolean;
  responseStatusCode: number;
  responseCode: string;
}

export interface AuthorizationAuditRecorder {
  recordDenied(denial: AuthorizationDenial): Promise<void>;
}

export class ConcealedAuthorizationDeniedError extends DirectorProtocolError {
  constructor(
    resourceType: string,
    resourceId: string,
    readonly missingPermissions: readonly string[],
  ) {
    super(404, 'not_found', `The ${resourceType} was not found.`, false, {
      resource: resourceType,
      id: resourceId,
    });
  }
}

export async function executeAuthorized<T>(
  recorder: AuthorizationAuditRecorder | undefined,
  attempt: AuthorizationAttempt,
  operation: () => Promise<T>,
): Promise<T> {
  try {
    return await operation();
  } catch (error) {
    const denial = authorizationDenial(error, attempt);
    if (denial === null || recorder === undefined) {
      throw error;
    }
    await recorder.recordDenied(denial);
    throw error;
  }
}

function authorizationDenial(
  error: unknown,
  attempt: AuthorizationAttempt,
): AuthorizationDenial | null {
  if (error instanceof ConcealedAuthorizationDeniedError) {
    return {
      ...baseDenial(attempt),
      reasonCodes: ['permission_missing'],
      missingPermissions: error.missingPermissions,
      responseConcealed: true,
      responseStatusCode: error.statusCode,
      responseCode: error.code,
    };
  }
  if (
    !(error instanceof DirectorProtocolError) ||
    error.statusCode !== 403 ||
    error.code !== 'access_denied'
  ) {
    return null;
  }
  const missingPermissions = stringArray(error.details.missing_permissions);
  const explicitReasonCodes = stringArray(error.details.reason_codes);
  return {
    ...baseDenial(attempt),
    reasonCodes:
      explicitReasonCodes.length > 0
        ? explicitReasonCodes
        : missingPermissions.length > 0
          ? ['permission_missing']
          : ['access_denied'],
    missingPermissions,
    responseConcealed: false,
    responseStatusCode: error.statusCode,
    responseCode: error.code,
  };
}

function baseDenial(attempt: AuthorizationAttempt) {
  return {
    actorUserId: attempt.actorUserId,
    principalUserId: attempt.principalUserId ?? attempt.actorUserId,
    action: attempt.action,
    resourceType: attempt.resourceType,
    resourceId: attempt.resourceId,
    projectId: attempt.projectId,
    requestId: attempt.requestId,
  };
}

function stringArray(value: unknown): string[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return [...new Set(value.filter((item): item is string => typeof item === 'string'))];
}
