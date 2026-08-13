export type ConfirmationStatus =
  | 'pending'
  | 'approved'
  | 'rejected'
  | 'expired'
  | 'consumed'
  | 'revoked';

export interface Project {
  id: string;
  title: string;
  description: string | null;
  status: 'active' | 'archived';
  owner_user_id: string;
  created_at: string;
  updated_at: string;
  archived_at: string | null;
}

export interface Confirmation {
  id: string;
  operation: string;
  target_type: string;
  target_id: string;
  project_id: string;
  requested_by_user_id: string;
  decided_by_user_id: string | null;
  authorization_decision_id: string;
  request_id: string;
  status: ConfirmationStatus;
  payload_hash: string;
  summary: string;
  created_at: string;
  expires_at: string;
  decided_at: string | null;
  consumed_at: string | null;
}

export type DecisionStatus = 'draft' | 'proposed' | 'approved' | 'rejected' | 'superseded';
export type SensitivityLevel = 'public' | 'internal' | 'confidential' | 'restricted';
export type RelationshipEndpointType =
  | 'memory_object'
  | 'decision'
  | 'open_question'
  | 'task'
  | 'agent_run';
export type RelationshipType =
  | 'references'
  | 'depends_on'
  | 'contradicts'
  | 'supersedes'
  | 'explains'
  | 'implements'
  | 'belongs_to'
  | 'derived_from';

export interface RelationshipInput {
  target_type: RelationshipEndpointType;
  target_id: string;
  relation_type: RelationshipType;
  description?: string | null;
}

export interface DecisionCreateInput {
  project_id: string;
  title: string;
  decision_text: string;
  rationale?: string | null;
  status: 'draft' | 'proposed';
  sensitivity_level: SensitivityLevel;
  relationships: RelationshipInput[];
}

export interface DecisionSupersedeInput {
  title: string;
  decision_text: string;
  rationale?: string | null;
  sensitivity_level: SensitivityLevel;
  relationships: RelationshipInput[];
}

export interface Decision {
  id: string;
  memory_object_id: string;
  project_id: string;
  topic_id: string | null;
  title: string;
  decision_text: string;
  rationale: string | null;
  status: DecisionStatus;
  supersedes_decision_id: string | null;
  decided_by_user_id: string | null;
  decided_at: string | null;
  sensitivity_level: SensitivityLevel;
  created_at: string;
  updated_at: string;
}

export interface DecisionSupersedeResponse {
  superseded_decision: Decision;
  new_decision: Decision;
}

export interface DecisionProvenance {
  decision: Decision;
  provenance_complete: true;
  relationships: Array<{
    id: string;
    source_type: RelationshipEndpointType;
    source_id: string;
    target_type: RelationshipEndpointType;
    target_id: string;
    relation_type: RelationshipType;
    description: string | null;
    created_by_user_id: string;
    created_at: string;
  }>;
  related_memory_objects: Array<{
    id: string;
    type: string;
    title: string;
    current_version_id: string | null;
    sensitivity_level: SensitivityLevel;
  }>;
  agent_runs: Array<{
    id: string;
    task_id: string;
    agent_type: string;
    provider: string;
    model: string | null;
    status: string;
    deployment_class: 'internal' | 'external';
    context_set_hash: string | null;
    result_memory_object_id: string | null;
    requested_by_user_id: string;
    origin_request_id: string;
    created_at: string;
    dispatched_at: string | null;
    started_at: string | null;
    finished_at: string | null;
  }>;
  source_versions: Array<{
    agent_run_id: string;
    position: number;
    memory_object_id: string;
    memory_object_title: string;
    document_version_id: string;
    version_number: number;
    file_name: string;
    file_type: string;
    content_hash: string;
    size_bytes: number;
    access_reason: string;
    frozen_sensitivity_level: SensitivityLevel;
    current_sensitivity_level: SensitivityLevel;
  }>;
  audit_events: Array<{
    id: string;
    actor_type: string;
    actor_id: string | null;
    action: string;
    target_type: string;
    target_id: string;
    request_id: string;
    created_at: string;
  }>;
}

interface Page<T> {
  items: T[];
  next_cursor: string | null;
}

interface SessionResponse {
  access_token: string;
}

interface ErrorResponse {
  error?: { code?: string; message?: string; details?: Record<string, unknown> };
}

const apiBase = (import.meta.env.VITE_DIRECTOR_API_BASE as string | undefined) ?? '/api/v1';
const staticToken = import.meta.env.VITE_DIRECTOR_STATIC_TOKEN as string | undefined;
const tokenKey = 'dirizhor.session.token';
export const oidcLoginUrl = `${apiBase.replace(/\/$/, '')}/auth/oidc/start`;
export const localLoginEnabled =
  (import.meta.env.VITE_DIRECTOR_LOCAL_LOGIN_ENABLED as string | undefined) === 'true';

export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
    readonly details: Readonly<Record<string, unknown>> = {},
  ) {
    super(message);
    this.name = 'ApiError';
  }
}

export async function login(loginValue: string, password: string): Promise<void> {
  const response = await apiRequest<SessionResponse>('/auth/sessions', {
    method: 'POST',
    body: JSON.stringify({ login: loginValue, password }),
    authenticated: false,
  });
  sessionStorage.setItem(tokenKey, response.access_token);
}

export async function logout(): Promise<void> {
  try {
    await apiRequest<null>('/auth/sessions/current', { method: 'DELETE' });
  } finally {
    sessionStorage.removeItem(tokenKey);
  }
}

export function clearSession(): void {
  sessionStorage.removeItem(tokenKey);
}

export function listProjects(cursor?: string): Promise<Page<Project>> {
  const query = new URLSearchParams({ limit: '100' });
  if (cursor !== undefined) query.set('cursor', cursor);
  return apiRequest(`/projects?${query.toString()}`);
}

export function listConfirmations(
  projectId: string,
  status: ConfirmationStatus,
  cursor?: string,
): Promise<Page<Confirmation>> {
  const query = new URLSearchParams({ project_id: projectId, status, limit: '20' });
  if (cursor !== undefined) query.set('cursor', cursor);
  return apiRequest(`/confirmations?${query.toString()}`);
}

export function decideConfirmation(
  confirmationId: string,
  decision: 'approve' | 'reject',
): Promise<Confirmation> {
  return apiRequest(`/confirmations/${encodeURIComponent(confirmationId)}:${decision}`, {
    method: 'POST',
  });
}

export function createDecision(input: DecisionCreateInput): Promise<Decision> {
  return apiRequest('/decisions', {
    method: 'POST',
    body: JSON.stringify(input),
  });
}

export function getDecisionProvenance(decisionId: string): Promise<DecisionProvenance> {
  return apiRequest(`/decisions/${encodeURIComponent(decisionId)}/provenance`);
}

export function requestDecisionApproval(decisionId: string): Promise<Decision> {
  return apiRequest(`/decisions/${encodeURIComponent(decisionId)}:approve`, {
    method: 'POST',
  });
}

export function supersedeDecision(
  decisionId: string,
  input: DecisionSupersedeInput,
): Promise<DecisionSupersedeResponse> {
  return apiRequest(`/decisions/${encodeURIComponent(decisionId)}:supersede`, {
    method: 'POST',
    body: JSON.stringify(input),
  });
}

async function apiRequest<T>(
  path: string,
  options: RequestInit & { authenticated?: boolean } = {},
  retryWithoutBrowserBearer = true,
): Promise<T> {
  const authenticated = options.authenticated ?? true;
  const headers = new Headers(options.headers);
  headers.set('x-request-id', crypto.randomUUID());
  if (options.body !== undefined) headers.set('content-type', 'application/json');
  const bearer = authenticated ? token() : null;
  if (bearer !== null) headers.set('authorization', `Bearer ${bearer}`);
  const response = await fetch(`${apiBase}${path}`, {
    ...options,
    headers,
    credentials: 'same-origin',
  });
  if (
    response.status === 401 &&
    authenticated &&
    bearer !== null &&
    staticToken === undefined &&
    retryWithoutBrowserBearer
  ) {
    sessionStorage.removeItem(tokenKey);
    return apiRequest(path, options, false);
  }
  if (response.ok) {
    if (response.status === 204) return null as T;
    return response.json() as Promise<T>;
  }
  const payload = await safeErrorPayload(response);
  throw new ApiError(
    response.status,
    payload.error?.code ?? 'request_failed',
    payload.error?.message ?? `Director API вернул ${response.status}.`,
    payload.error?.details ?? {},
  );
}

function token(): string | null {
  return staticToken ?? sessionStorage.getItem(tokenKey);
}

async function safeErrorPayload(response: Response): Promise<ErrorResponse> {
  try {
    return await response.json() as ErrorResponse;
  } catch {
    return {};
  }
}
