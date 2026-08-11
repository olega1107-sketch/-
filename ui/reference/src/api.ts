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

interface Page<T> {
  items: T[];
  next_cursor: string | null;
}

interface SessionResponse {
  access_token: string;
}

interface ErrorResponse {
  error?: { code?: string; message?: string };
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
