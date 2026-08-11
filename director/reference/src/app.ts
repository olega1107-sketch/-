import { randomUUID } from 'node:crypto';
import type { ServerOptions as HttpsServerOptions } from 'node:https';

import type { TypeBoxTypeProvider } from '@fastify/type-provider-typebox';
import cookie from '@fastify/cookie';
import multipart from '@fastify/multipart';
import { Type } from '@sinclair/typebox';
import { Value } from '@sinclair/typebox/value';
import Fastify, { type FastifyRequest } from 'fastify';

import {
  executeAuthorized,
  type AuthorizationAuditRecorder,
} from './authorization-audit.js';
import {
  AgentResultSaveRequestSchema,
  AgentRunResultSchema,
} from './agent-result-protocol.js';
import type { AgentResultService } from './agent-result-service.js';
import type { DirectorService } from './director-service.js';
import {
  ConfirmationIdParamsSchema,
  ConfirmationListQuerySchema,
  ConfirmationPageSchema,
  ConfirmationSchema,
} from './confirmation-protocol.js';
import type { ConfirmationService } from './confirmation-service.js';
import { DirectorProtocolError } from './errors.js';
import type { MemoryIngestService } from './memory-ingest-service.js';
import type { AuthenticatedUser, UserAuthenticator } from './memory-ports.js';
import {
  oidcTransactionCookieName,
  protectedAuthenticationCookieOptions,
  userSessionCookieName,
} from './auth-cookie.js';
import {
  BrowserAuthenticationHeadersSchema,
  OidcCallbackQuerySchema,
  OidcLogoutResponseSchema,
} from './oidc-protocol.js';
import type { OidcService } from './oidc-service.js';
import type { ServiceAuthenticator } from './ports.js';
import {
  MemoryObjectIdParamsSchema,
  MemoryObjectPageSchema,
  MemoryObjectSchema,
  MemoryObjectSearchQuerySchema,
  MemoryUploadMetadataSchema,
  ProjectListQuerySchema,
  ProjectPageSchema,
  PublicErrorResponseSchema,
  PublicRequestHeadersSchema,
  type MemoryUploadMetadata,
} from './public-protocol.js';
import type { PublicQueryService } from './public-query-service.js';
import {
  AgentRunIdParamsSchema,
  ContextBundleRedeemRequestSchema,
  ContextBundleSchema,
  EventHeadersSchema,
  GatewayEventSchema,
  ProtocolErrorResponseSchema,
  RedeemHeadersSchema,
} from './protocol.js';
import type { TaskService } from './task-service.js';
import {
  IssuedUserSessionSchema,
  SessionCreateSchema,
} from './session-protocol.js';
import type { SessionService } from './session-service.js';
import {
  AgentRunCreateSchema,
  AgentRunSchema,
  TaskContextSearchRequestSchema,
  TaskContextSearchResponseSchema,
  TaskCreateSchema,
  TaskIdParamsSchema,
  TaskSchema,
  TaskTimelinePageSchema,
  TaskTimelineQuerySchema,
} from './task-protocol.js';

export interface DirectorAppOptions {
  service: DirectorService;
  authenticator: ServiceAuthenticator;
  https?: HttpsServerOptions | null;
  readiness?: () => Promise<void>;
  trustedProxies?: string[];
  bodyLimitBytes?: number;
  publicApi?: {
    memoryIngest: MemoryIngestService;
    authenticator: UserAuthenticator;
    maxUploadBytes?: number;
    tasks?: TaskService;
    agentResults?: AgentResultService;
    confirmations?: ConfirmationService;
    queries?: PublicQueryService;
    sessions?: {
      service: SessionService;
      allowLocalPasswordIssuance: boolean;
      oidc?: {
        service: OidcService;
        postLoginRedirectUri: string;
      };
    };
    authorizationAudit?: AuthorizationAuditRecorder;
  };
}

const errorResponses = {
  400: ProtocolErrorResponseSchema,
  401: ProtocolErrorResponseSchema,
  403: ProtocolErrorResponseSchema,
  404: ProtocolErrorResponseSchema,
  409: ProtocolErrorResponseSchema,
  410: ProtocolErrorResponseSchema,
  413: ProtocolErrorResponseSchema,
  422: ProtocolErrorResponseSchema,
  429: ProtocolErrorResponseSchema,
  500: ProtocolErrorResponseSchema,
  503: ProtocolErrorResponseSchema,
};
const agentRunRouteParameter =
  ':agent_run_id(^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-8][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$)';
const confirmationRouteParameter =
  ':confirmation_id(^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-8][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$)';
const memoryObjectRouteParameter =
  ':memory_object_id(^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-8][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$)';
const publicErrorResponses = {
  400: PublicErrorResponseSchema,
  401: PublicErrorResponseSchema,
  403: PublicErrorResponseSchema,
  404: PublicErrorResponseSchema,
  409: PublicErrorResponseSchema,
  413: PublicErrorResponseSchema,
  428: PublicErrorResponseSchema,
  429: PublicErrorResponseSchema,
  500: PublicErrorResponseSchema,
};
const HealthStatusSchema = Type.Object(
  { status: Type.Union([Type.Literal('ok'), Type.Literal('unavailable')]) },
  { additionalProperties: false },
);
const multipartLimitCodes = new Set([
  'FST_PARTS_LIMIT',
  'FST_FILES_LIMIT',
  'FST_FIELDS_LIMIT',
  'FST_REQ_FILE_TOO_LARGE',
]);
const malformedMultipartCodes = new Set([
  'FST_PROTO_VIOLATION',
  'FST_INVALID_MULTIPART_CONTENT_TYPE',
  'FST_INVALID_JSON_FIELD_ERROR',
  'FST_MP_PREMATURE_CLOSE',
]);
const uploadSingletonFields = new Set([
  'project_id',
  'topic_id',
  'type',
  'title',
  'summary',
  'sensitivity_level',
]);
const uploadFields = new Set([...uploadSingletonFields, 'keywords']);

export function buildDirectorApp(options: DirectorAppOptions) {
  const app = Fastify({
    logger: false,
    https: options.https ?? null,
    bodyLimit: options.bodyLimitBytes ?? 5 * 1024 * 1024,
    trustProxy:
      options.trustedProxies === undefined || options.trustedProxies.length === 0
        ? false
        : options.trustedProxies,
  }).withTypeProvider<TypeBoxTypeProvider>();
  void app.register(cookie);
  const userPrincipals = new WeakMap<FastifyRequest, AuthenticatedUser>();

  app.get(
    '/health/live',
    { schema: { response: { 200: HealthStatusSchema } } },
    async (_request, reply) =>
      reply.header('cache-control', 'no-store').status(200).send({ status: 'ok' }),
  );
  app.get(
    '/health/ready',
    { schema: { response: { 200: HealthStatusSchema, 503: HealthStatusSchema } } },
    async (_request, reply) => {
      try {
        await options.readiness?.();
        return reply
          .header('cache-control', 'no-store')
          .status(200)
          .send({ status: 'ok' });
      } catch {
        return reply
          .header('cache-control', 'no-store')
          .status(503)
          .send({ status: 'unavailable' });
      }
    },
  );

  const publicApi = options.publicApi;
  if (publicApi !== undefined) {
    const sessions = publicApi.sessions;
    if (sessions !== undefined) {
      if (sessions.oidc !== undefined) {
        app.get(
          '/api/v1/auth/oidc/start',
          {
            schema: {
              headers: BrowserAuthenticationHeadersSchema,
            },
          },
          async (request, reply) => {
            const requestId = requestIdFor(request);
            const started = await sessions.oidc!.service.startLogin(
              sessionRequestContext(request, requestId),
            );
            return reply
              .header('x-request-id', requestId)
              .header('cache-control', 'no-store')
              .header('pragma', 'no-cache')
              .header('referrer-policy', 'no-referrer')
              .header('content-security-policy', "default-src 'none'")
              .setCookie(oidcTransactionCookieName, started.browserToken, {
                ...protectedAuthenticationCookieOptions,
                maxAge: started.maxAgeSeconds,
                expires: new Date(started.expiresAt),
              })
              .status(302)
              .header('location', started.authorizationUrl)
              .send();
          },
        );

        app.get(
          '/api/v1/auth/oidc/callback',
          {
            schema: {
              headers: BrowserAuthenticationHeadersSchema,
              querystring: OidcCallbackQuerySchema,
            },
          },
          async (request, reply) => {
            const requestId = requestIdFor(request);
            const baseReply = reply
              .header('x-request-id', requestId)
              .header('cache-control', 'no-store')
              .header('pragma', 'no-cache')
              .header('referrer-policy', 'no-referrer')
              .header('content-security-policy', "default-src 'none'")
              .clearCookie(
                oidcTransactionCookieName,
                protectedAuthenticationCookieOptions,
              );
            try {
              const issued = await sessions.oidc!.service.completeLogin(
                request.query,
                request.cookies[oidcTransactionCookieName],
                sessionRequestContext(request, requestId),
              );
              return baseReply
                .setCookie(userSessionCookieName, issued.access_token, {
                  ...protectedAuthenticationCookieOptions,
                  maxAge: secondsBetween(
                    new Date(issued.session.created_at),
                    new Date(issued.session.expires_at),
                  ),
                  expires: new Date(issued.session.expires_at),
                })
                .status(303)
                .header('location', sessions.oidc!.postLoginRedirectUri)
                .send();
            } catch (error) {
              if (error instanceof DirectorProtocolError) {
                const redirect = new URL(sessions.oidc!.postLoginRedirectUri);
                redirect.searchParams.set('auth_error', error.code);
                return baseReply
                  .status(303)
                  .header('location', redirect.href)
                  .send();
              }
              throw error;
            }
          },
        );

        app.post(
          '/api/v1/auth/oidc/logout',
          {
            schema: {
              headers: PublicRequestHeadersSchema,
              response: { 200: OidcLogoutResponseSchema, ...publicErrorResponses },
            },
            preHandler: async (request) => {
              const principal = await authenticateUser(
                publicApi.authenticator,
                request,
              );
              userPrincipals.set(request, principal);
            },
          },
          async (request, reply) => {
            const requestId = requestIdFor(request);
            const principal = requiredUserPrincipal(userPrincipals, request);
            const logoutUrl = await sessions.oidc!.service.logoutCurrentSession(
              principal.userId,
              principal.sessionId,
              principal.authenticationMethod,
              sessionRequestContext(request, requestId),
            );
            return reply
              .header('x-request-id', requestId)
              .header('cache-control', 'no-store')
              .header('pragma', 'no-cache')
              .clearCookie(
                userSessionCookieName,
                protectedAuthenticationCookieOptions,
              )
              .status(200)
              .send({ logout_url: logoutUrl });
          },
        );
      }
      if (sessions.allowLocalPasswordIssuance) {
        app.post(
          '/api/v1/auth/sessions',
          {
            schema: {
              headers: PublicRequestHeadersSchema,
              body: SessionCreateSchema,
              response: { 201: IssuedUserSessionSchema, ...publicErrorResponses },
            },
          },
          async (request, reply) => {
            const requestId = requestIdFor(request);
            const issued = await sessions.service.createSession(
              request.body,
              sessionRequestContext(request, requestId),
            );
            return reply
              .header('x-request-id', requestId)
              .header('cache-control', 'no-store')
              .header('pragma', 'no-cache')
              .status(201)
              .send(issued);
          },
        );
      }
      app.delete(
        '/api/v1/auth/sessions/current',
        {
          schema: {
            headers: PublicRequestHeadersSchema,
            response: { 204: Type.Null(), ...publicErrorResponses },
          },
          preHandler: async (request) => {
            const principal = await authenticateUser(publicApi.authenticator, request);
            userPrincipals.set(request, principal);
          },
        },
        async (request, reply) => {
          const requestId = requestIdFor(request);
          const principal = requiredUserPrincipal(userPrincipals, request);
          await sessions.service.revokeCurrentSession(
            principal.userId,
            principal.sessionId,
            sessionRequestContext(request, requestId),
          );
          return reply
            .header('x-request-id', requestId)
            .clearCookie(userSessionCookieName, protectedAuthenticationCookieOptions)
            .status(204)
            .send(null);
        },
      );
    }

    const queries = publicApi.queries;
    if (queries !== undefined) {
      app.get(
        '/api/v1/projects',
        {
          schema: {
            querystring: ProjectListQuerySchema,
            headers: PublicRequestHeadersSchema,
            response: { 200: ProjectPageSchema, ...publicErrorResponses },
          },
          preHandler: async (request) => {
            const principal = await authenticateUser(publicApi.authenticator, request);
            userPrincipals.set(request, principal);
          },
        },
        async (request, reply) => {
          const requestId = requestIdFor(request);
          const principal = requiredUserPrincipal(userPrincipals, request);
          const projects = await executeAuthorized(
            publicApi.authorizationAudit,
            {
              actorUserId: principal.userId,
              action: 'project.read',
              resourceType: 'project_collection',
              resourceId: principal.userId,
              projectId: null,
              requestId,
            },
            () => queries.listProjects(principal.userId, requestId, request.query),
          );
          return reply.header('x-request-id', requestId).status(200).send(projects);
        },
      );
    }

    const maxUploadBytes = publicApi.maxUploadBytes ?? 25 * 1024 * 1024;
    if (!Number.isSafeInteger(maxUploadBytes) || maxUploadBytes < 1) {
      throw new Error('Public document upload limit must be a positive safe integer.');
    }
    void app.register(multipart, {
      throwFileSizeLimit: true,
      limits: multipartLimits(maxUploadBytes),
    });
    app.post(
      '/api/v1/memory-objects::upload',
      {
        schema: {
          headers: PublicRequestHeadersSchema,
          response: { 201: MemoryObjectSchema, ...publicErrorResponses },
        },
        preHandler: async (request) => {
          const principal = await authenticateUser(publicApi.authenticator, request);
          userPrincipals.set(request, principal);
        },
      },
      async (request, reply) => {
        const requestId = requestIdFor(request);
        const principal = userPrincipals.get(request);
        if (principal === undefined) {
          throw new Error('Authenticated user principal is missing from the request.');
        }
        const upload = await parseMemoryUpload(request, maxUploadBytes);
        const memoryObject = await executeAuthorized(
          publicApi.authorizationAudit,
          {
            actorUserId: principal.userId,
            action: 'memory_object.create',
            resourceType: 'project',
            resourceId: upload.metadata.project_id,
            projectId: upload.metadata.project_id,
            requestId,
          },
          () =>
            publicApi.memoryIngest.upload({
              userId: principal.userId,
              requestId,
              metadata: upload.metadata,
              fileName: upload.fileName,
              fileType: upload.fileType,
              content: upload.content,
            }),
        );
        return reply.header('x-request-id', requestId).status(201).send(memoryObject);
      },
    );

    if (queries !== undefined) {
      app.get(
        '/api/v1/memory-objects/search',
        {
          schema: {
            headers: PublicRequestHeadersSchema,
            querystring: MemoryObjectSearchQuerySchema,
            response: { 200: MemoryObjectPageSchema, ...publicErrorResponses },
          },
          preHandler: async (request) => {
            const principal = await authenticateUser(publicApi.authenticator, request);
            userPrincipals.set(request, principal);
          },
        },
        async (request, reply) => {
          const requestId = requestIdFor(request);
          const principal = requiredUserPrincipal(userPrincipals, request);
          const page = await executeAuthorized(
            publicApi.authorizationAudit,
            {
              actorUserId: principal.userId,
              action: 'memory_object.search',
              resourceType: 'project',
              resourceId: request.query.project_id,
              projectId: request.query.project_id,
              requestId,
            },
            () => queries.searchMemoryObjects(principal.userId, requestId, request.query),
          );
          return reply.header('x-request-id', requestId).status(200).send(page);
        },
      );

      app.get(
        `/api/v1/memory-objects/${memoryObjectRouteParameter}`,
        {
          schema: {
            params: MemoryObjectIdParamsSchema,
            headers: PublicRequestHeadersSchema,
            response: { 200: MemoryObjectSchema, ...publicErrorResponses },
          },
          preHandler: async (request) => {
            const principal = await authenticateUser(publicApi.authenticator, request);
            userPrincipals.set(request, principal);
          },
        },
        async (request, reply) => {
          const requestId = requestIdFor(request);
          const principal = requiredUserPrincipal(userPrincipals, request);
          const memoryObject = await executeAuthorized(
            publicApi.authorizationAudit,
            {
              actorUserId: principal.userId,
              action: 'memory_object.read',
              resourceType: 'memory_object',
              resourceId: request.params.memory_object_id,
              projectId: null,
              requestId,
            },
            () =>
              queries.getMemoryObject(
                principal.userId,
                requestId,
                request.params.memory_object_id,
              ),
          );
          return reply.header('x-request-id', requestId).status(200).send(memoryObject);
        },
      );

      app.post(
        '/api/v1/tasks/:task_id/context::search',
        {
          schema: {
            params: TaskIdParamsSchema,
            headers: PublicRequestHeadersSchema,
            body: TaskContextSearchRequestSchema,
            response: { 200: TaskContextSearchResponseSchema, ...publicErrorResponses },
          },
          preHandler: async (request) => {
            const principal = await authenticateUser(publicApi.authenticator, request);
            userPrincipals.set(request, principal);
          },
        },
        async (request, reply) => {
          const requestId = requestIdFor(request);
          const principal = requiredUserPrincipal(userPrincipals, request);
          const result = await executeAuthorized(
            publicApi.authorizationAudit,
            {
              actorUserId: principal.userId,
              action: 'memory_object.search',
              resourceType: 'task',
              resourceId: request.params.task_id,
              projectId: null,
              requestId,
            },
            () =>
              queries.searchTaskContext(
                principal.userId,
                requestId,
                request.params.task_id,
                request.body,
              ),
          );
          return reply.header('x-request-id', requestId).status(200).send(result);
        },
      );

      app.get(
        '/api/v1/tasks/:task_id/timeline',
        {
          schema: {
            params: TaskIdParamsSchema,
            headers: PublicRequestHeadersSchema,
            querystring: TaskTimelineQuerySchema,
            response: { 200: TaskTimelinePageSchema, ...publicErrorResponses },
          },
          preHandler: async (request) => {
            const principal = await authenticateUser(publicApi.authenticator, request);
            userPrincipals.set(request, principal);
          },
        },
        async (request, reply) => {
          const requestId = requestIdFor(request);
          const principal = requiredUserPrincipal(userPrincipals, request);
          const page = await executeAuthorized(
            publicApi.authorizationAudit,
            {
              actorUserId: principal.userId,
              action: 'task.read',
              resourceType: 'task',
              resourceId: request.params.task_id,
              projectId: null,
              requestId,
            },
            () =>
              queries.getTaskTimeline(
                principal.userId,
                requestId,
                request.params.task_id,
                request.query,
              ),
          );
          return reply.header('x-request-id', requestId).status(200).send(page);
        },
      );
    }

    const tasks = publicApi.tasks;
    if (tasks !== undefined) {
      app.post(
        '/api/v1/tasks',
        {
          schema: {
            headers: PublicRequestHeadersSchema,
            body: TaskCreateSchema,
            response: { 201: TaskSchema, ...publicErrorResponses },
          },
          preHandler: async (request) => {
            const principal = await authenticateUser(publicApi.authenticator, request);
            userPrincipals.set(request, principal);
          },
        },
        async (request, reply) => {
          const requestId = requestIdFor(request);
          const principal = requiredUserPrincipal(userPrincipals, request);
          const task = await executeAuthorized(
            publicApi.authorizationAudit,
            {
              actorUserId: principal.userId,
              action: 'task.create',
              resourceType: 'project',
              resourceId: request.body.project_id,
              projectId: request.body.project_id,
              requestId,
            },
            () => tasks.createTask(principal.userId, requestId, request.body),
          );
          return reply.header('x-request-id', requestId).status(201).send(task);
        },
      );

      app.get(
        '/api/v1/tasks/:task_id',
        {
          schema: {
            params: TaskIdParamsSchema,
            headers: PublicRequestHeadersSchema,
            response: { 200: TaskSchema, ...publicErrorResponses },
          },
          preHandler: async (request) => {
            const principal = await authenticateUser(publicApi.authenticator, request);
            userPrincipals.set(request, principal);
          },
        },
        async (request, reply) => {
          const requestId = requestIdFor(request);
          const principal = requiredUserPrincipal(userPrincipals, request);
          const task = await executeAuthorized(
            publicApi.authorizationAudit,
            {
              actorUserId: principal.userId,
              action: 'task.read',
              resourceType: 'task',
              resourceId: request.params.task_id,
              projectId: null,
              requestId,
            },
            () => tasks.getTask(principal.userId, requestId, request.params.task_id),
          );
          return reply.header('x-request-id', requestId).status(200).send(task);
        },
      );

      app.post(
        '/api/v1/tasks/:task_id/agent-runs',
        {
          schema: {
            params: TaskIdParamsSchema,
            headers: PublicRequestHeadersSchema,
            body: AgentRunCreateSchema,
            response: { 202: AgentRunSchema, ...publicErrorResponses },
          },
          preHandler: async (request) => {
            const principal = await authenticateUser(publicApi.authenticator, request);
            userPrincipals.set(request, principal);
          },
        },
        async (request, reply) => {
          const requestId = requestIdFor(request);
          const principal = requiredUserPrincipal(userPrincipals, request);
          const run = await executeAuthorized(
            publicApi.authorizationAudit,
            {
              actorUserId: principal.userId,
              action: 'agent_run.create',
              resourceType: 'task',
              resourceId: request.params.task_id,
              projectId: null,
              requestId,
            },
            () =>
              tasks.createAgentRun(
                principal.userId,
                request.params.task_id,
                requestId,
                request.body,
              ),
          );
          return reply.header('x-request-id', requestId).status(202).send(run);
        },
      );

      app.get(
        `/api/v1/agent-runs/${agentRunRouteParameter}`,
        {
          schema: {
            params: AgentRunIdParamsSchema,
            headers: PublicRequestHeadersSchema,
            response: { 200: AgentRunSchema, ...publicErrorResponses },
          },
          preHandler: async (request) => {
            const principal = await authenticateUser(publicApi.authenticator, request);
            userPrincipals.set(request, principal);
          },
        },
        async (request, reply) => {
          const requestId = requestIdFor(request);
          const principal = requiredUserPrincipal(userPrincipals, request);
          const run = await executeAuthorized(
            publicApi.authorizationAudit,
            {
              actorUserId: principal.userId,
              action: 'agent_run.read',
              resourceType: 'agent_run',
              resourceId: request.params.agent_run_id,
              projectId: null,
              requestId,
            },
            () => tasks.getAgentRun(principal.userId, requestId, request.params.agent_run_id),
          );
          return reply.header('x-request-id', requestId).status(200).send(run);
        },
      );
    }

    const agentResults = publicApi.agentResults;
    if (agentResults !== undefined) {
      app.get(
        `/api/v1/agent-runs/${agentRunRouteParameter}/result`,
        {
          schema: {
            params: AgentRunIdParamsSchema,
            headers: PublicRequestHeadersSchema,
            response: { 200: AgentRunResultSchema, ...publicErrorResponses },
          },
          preHandler: async (request) => {
            const principal = await authenticateUser(publicApi.authenticator, request);
            userPrincipals.set(request, principal);
          },
        },
        async (request, reply) => {
          const requestId = requestIdFor(request);
          const principal = requiredUserPrincipal(userPrincipals, request);
          const result = await executeAuthorized(
            publicApi.authorizationAudit,
            {
              actorUserId: principal.userId,
              action: 'agent_run.read',
              resourceType: 'agent_run',
              resourceId: request.params.agent_run_id,
              projectId: null,
              requestId,
            },
            () =>
              agentResults.getAgentRunResult(
                principal.userId,
                requestId,
                request.params.agent_run_id,
              ),
          );
          return reply.header('x-request-id', requestId).status(200).send(result);
        },
      );

      app.post(
        `/api/v1/agent-runs/${agentRunRouteParameter}/result::save`,
        {
          schema: {
            params: AgentRunIdParamsSchema,
            headers: PublicRequestHeadersSchema,
            body: AgentResultSaveRequestSchema,
            response: { 201: MemoryObjectSchema, ...publicErrorResponses },
          },
          preHandler: async (request) => {
            const principal = await authenticateUser(publicApi.authenticator, request);
            userPrincipals.set(request, principal);
          },
        },
        async (request, reply) => {
          const requestId = requestIdFor(request);
          const principal = requiredUserPrincipal(userPrincipals, request);
          const memoryObject = await executeAuthorized(
            publicApi.authorizationAudit,
            {
              actorUserId: principal.userId,
              action: 'ai_result.save',
              resourceType: 'agent_run',
              resourceId: request.params.agent_run_id,
              projectId: null,
              requestId,
            },
            () =>
              agentResults.saveAgentRunResult(
                principal.userId,
                request.params.agent_run_id,
                requestId,
                request.body,
              ),
          );
          return reply.header('x-request-id', requestId).status(201).send(memoryObject);
        },
      );
    }

    const confirmations = publicApi.confirmations;
    if (confirmations !== undefined) {
      app.get(
        '/api/v1/confirmations',
        {
          schema: {
            querystring: ConfirmationListQuerySchema,
            headers: PublicRequestHeadersSchema,
            response: { 200: ConfirmationPageSchema, ...publicErrorResponses },
          },
          preHandler: async (request) => {
            const principal = await authenticateUser(publicApi.authenticator, request);
            userPrincipals.set(request, principal);
          },
        },
        async (request, reply) => {
          const requestId = requestIdFor(request);
          const principal = requiredUserPrincipal(userPrincipals, request);
          const page = await executeAuthorized(
            publicApi.authorizationAudit,
            {
              actorUserId: principal.userId,
              action: 'confirmation.read',
              resourceType: 'project',
              resourceId: request.query.project_id,
              projectId: request.query.project_id,
              requestId,
            },
            () => confirmations.listConfirmations(principal.userId, requestId, request.query),
          );
          return reply.header('x-request-id', requestId).status(200).send(page);
        },
      );

      app.get(
        `/api/v1/confirmations/${confirmationRouteParameter}`,
        {
          schema: {
            params: ConfirmationIdParamsSchema,
            headers: PublicRequestHeadersSchema,
            response: { 200: ConfirmationSchema, ...publicErrorResponses },
          },
          preHandler: async (request) => {
            const principal = await authenticateUser(publicApi.authenticator, request);
            userPrincipals.set(request, principal);
          },
        },
        async (request, reply) => {
          const requestId = requestIdFor(request);
          const principal = requiredUserPrincipal(userPrincipals, request);
          const confirmation = await executeAuthorized(
            publicApi.authorizationAudit,
            {
              actorUserId: principal.userId,
              action: 'confirmation.read',
              resourceType: 'confirmation',
              resourceId: request.params.confirmation_id,
              projectId: null,
              requestId,
            },
            () =>
              confirmations.getConfirmation(
                principal.userId,
                requestId,
                request.params.confirmation_id,
              ),
          );
          return reply.header('x-request-id', requestId).status(200).send(confirmation);
        },
      );

      app.post(
        `/api/v1/confirmations/${confirmationRouteParameter}::approve`,
        {
          schema: {
            params: ConfirmationIdParamsSchema,
            headers: PublicRequestHeadersSchema,
            response: { 200: ConfirmationSchema, ...publicErrorResponses },
          },
          preHandler: async (request) => {
            const principal = await authenticateUser(publicApi.authenticator, request);
            userPrincipals.set(request, principal);
          },
        },
        async (request, reply) => {
          const requestId = requestIdFor(request);
          const principal = requiredUserPrincipal(userPrincipals, request);
          const confirmation = await executeAuthorized(
            publicApi.authorizationAudit,
            {
              actorUserId: principal.userId,
              action: 'confirmation.approve',
              resourceType: 'confirmation',
              resourceId: request.params.confirmation_id,
              projectId: null,
              requestId,
            },
            () =>
              confirmations.approveConfirmation(
                principal.userId,
                request.params.confirmation_id,
                requestId,
              ),
          );
          return reply.header('x-request-id', requestId).status(200).send(confirmation);
        },
      );

      app.post(
        `/api/v1/confirmations/${confirmationRouteParameter}::reject`,
        {
          schema: {
            params: ConfirmationIdParamsSchema,
            headers: PublicRequestHeadersSchema,
            response: { 200: ConfirmationSchema, ...publicErrorResponses },
          },
          preHandler: async (request) => {
            const principal = await authenticateUser(publicApi.authenticator, request);
            userPrincipals.set(request, principal);
          },
        },
        async (request, reply) => {
          const requestId = requestIdFor(request);
          const principal = requiredUserPrincipal(userPrincipals, request);
          const confirmation = await executeAuthorized(
            publicApi.authorizationAudit,
            {
              actorUserId: principal.userId,
              action: 'confirmation.reject',
              resourceType: 'confirmation',
              resourceId: request.params.confirmation_id,
              projectId: null,
              requestId,
            },
            () =>
              confirmations.rejectConfirmation(
                principal.userId,
                request.params.confirmation_id,
                requestId,
              ),
          );
          return reply.header('x-request-id', requestId).status(200).send(confirmation);
        },
      );
    }
  }

  app.post(
    `/internal/v1/agent-runs/${agentRunRouteParameter}/context-bundle::redeem`,
    {
      schema: {
        params: AgentRunIdParamsSchema,
        headers: RedeemHeadersSchema,
        body: ContextBundleRedeemRequestSchema,
        response: { 200: ContextBundleSchema, ...errorResponses },
      },
      preHandler: async (request) => authenticate(options.authenticator, request),
    },
    async (request, reply) => {
      const requestId = requestIdFor(request);
      const bundle = await options.service.redeemContextBundle(
        request.params.agent_run_id,
        request.headers['x-agent-capability'],
        request.body,
        requestId,
      );
      return reply.header('x-request-id', requestId).status(200).send(bundle);
    },
  );

  app.post(
    `/internal/v1/agent-runs/${agentRunRouteParameter}/events`,
    {
      schema: {
        params: AgentRunIdParamsSchema,
        headers: EventHeadersSchema,
        body: GatewayEventSchema,
        response: { 204: Type.Null(), ...errorResponses },
      },
      preHandler: async (request) => authenticate(options.authenticator, request),
    },
    async (request, reply) => {
      const requestId = requestIdFor(request);
      await options.service.recordGatewayEvent(request.params.agent_run_id, request.body);
      return reply.header('x-request-id', requestId).status(204).send(null);
    },
  );

  app.setErrorHandler((error, request, reply) => {
    const requestId = requestIdFor(request);
    const publicRequest = request.url.startsWith('/api/v1/');
    const mapped = mapError(error, publicRequest);
    if (publicRequest) {
      void reply
        .header('x-request-id', requestId)
        .status(mapped.statusCode)
        .send({
          error: {
            code: mapped.code,
            message: mapped.message,
            details: mapped.details,
            request_id: requestId,
          },
        });
      return;
    }
    void reply
      .header('x-request-id', requestId)
      .status(mapped.statusCode)
      .send({
        error: {
          code: mapped.code,
          message: mapped.message,
          retryable: mapped.retryable,
          details: mapped.details,
        },
        request_id: requestId,
      });
  });

  return app;
}

async function authenticate(
  authenticator: ServiceAuthenticator,
  request: FastifyRequest,
): Promise<void> {
  const authorization = request.headers.authorization;
  await authenticator.authenticate({
    ...(typeof authorization === 'string' ? { authorization } : {}),
    socket: request.raw.socket,
  });
}

async function authenticateUser(
  authenticator: UserAuthenticator,
  request: FastifyRequest,
): Promise<AuthenticatedUser> {
  let authorization = request.headers.authorization;
  if (typeof authorization !== 'string') {
    const sessionToken = request.cookies[userSessionCookieName];
    if (sessionToken !== undefined) {
      assertCookieMutationOrigin(request, authenticator.cookieOrigin);
      authorization = `Bearer ${sessionToken}`;
    }
  }
  return authenticator.authenticate({
    ...(typeof authorization === 'string' ? { authorization } : {}),
    socket: request.raw.socket,
  });
}

function assertCookieMutationOrigin(
  request: FastifyRequest,
  expectedOrigin: string | undefined,
): void {
  if (request.method === 'GET' || request.method === 'HEAD' || request.method === 'OPTIONS') {
    return;
  }
  const originHeader = request.headers.origin;
  let origin: URL;
  try {
    origin = new URL(typeof originHeader === 'string' ? originHeader : 'invalid:');
  } catch {
    throw csrfError();
  }
  if (expectedOrigin === undefined || origin.origin !== expectedOrigin) {
    throw csrfError();
  }
}

function csrfError(): DirectorProtocolError {
  return new DirectorProtocolError(
    403,
    'csrf_check_failed',
    'Cookie-authenticated mutation failed the same-origin check.',
  );
}

function secondsBetween(start: Date, end: Date): number {
  return Math.max(1, Math.floor((end.getTime() - start.getTime()) / 1_000));
}

function requiredUserPrincipal(
  principals: WeakMap<FastifyRequest, AuthenticatedUser>,
  request: FastifyRequest,
): AuthenticatedUser {
  const principal = principals.get(request);
  if (principal === undefined) {
    throw new Error('Authenticated user principal is missing from the request.');
  }
  return principal;
}

function sessionRequestContext(
  request: FastifyRequest,
  requestId: string,
): { requestId: string; ipAddress: string | null; userAgent: string | null } {
  return {
    requestId,
    ipAddress: request.ip,
    userAgent:
      typeof request.headers['user-agent'] === 'string'
        ? request.headers['user-agent']
        : null,
  };
}

function requestIdFor(request: FastifyRequest): string {
  const candidate = request.headers['x-request-id'];
  if (
    typeof candidate === 'string' &&
    /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-8][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$/.test(
      candidate,
    )
  ) {
    return candidate;
  }
  return randomUUID();
}

interface MappedError {
  statusCode: number;
  code: string;
  message: string;
  retryable: boolean;
  details: Readonly<Record<string, unknown>>;
}

function mapError(error: unknown, publicRequest: boolean): MappedError {
  if (error instanceof DirectorProtocolError) {
    return {
      statusCode: error.statusCode,
      code: error.code,
      message: error.message,
      retryable: error.retryable,
      details: error.details,
    };
  }
  const code = fastifyErrorCode(error);
  if (code !== undefined && multipartLimitCodes.has(code)) {
    return {
      statusCode: 413,
      code: 'payload_too_large',
      message: 'The multipart upload exceeds an operational limit.',
      retryable: false,
      details: {},
    };
  }
  if (code !== undefined && malformedMultipartCodes.has(code)) {
    return {
      statusCode: 400,
      code: 'validation_error',
      message: 'A valid multipart/form-data request is required.',
      retryable: false,
      details: {},
    };
  }
  const fields = validationFields(error);
  if (fields !== undefined) {
    return {
      statusCode: 400,
      code: 'validation_error',
      message: publicRequest
        ? 'The request does not match the Director API contract.'
        : 'The request does not match the Agent Gateway protocol.',
      retryable: false,
      details: { fields },
    };
  }
  return {
    statusCode: 500,
    code: 'internal_error',
    message: publicRequest
      ? 'Director could not process the request.'
      : 'Director could not process the internal request.',
    retryable: false,
    details: {},
  };
}

interface ParsedMemoryUpload {
  metadata: MemoryUploadMetadata;
  fileName: string;
  fileType: string;
  content: Uint8Array;
}

async function parseMemoryUpload(
  request: FastifyRequest,
  maxUploadBytes: number,
): Promise<ParsedMemoryUpload> {
  if (!request.isMultipart()) {
    throw validationError(['request']);
  }
  const fields = new Map<string, string[]>();
  let file:
    | {
        fileName: string;
        fileType: string;
        content: Uint8Array;
      }
    | undefined;

  for await (const part of request.parts({ limits: multipartLimits(maxUploadBytes) })) {
    if (part.type === 'file') {
      const content = await part.toBuffer();
      if (part.fieldname !== 'file' || file !== undefined) {
        throw validationError([part.fieldname]);
      }
      file = {
        fileName: normalizedFileName(part.filename),
        fileType: part.mimetype.trim() || 'application/octet-stream',
        content,
      };
      continue;
    }
    if (
      !uploadFields.has(part.fieldname) ||
      part.fieldnameTruncated ||
      part.valueTruncated ||
      typeof part.value !== 'string'
    ) {
      throw validationError([part.fieldname]);
    }
    const values = fields.get(part.fieldname) ?? [];
    if (uploadSingletonFields.has(part.fieldname) && values.length > 0) {
      throw validationError([part.fieldname]);
    }
    values.push(part.value);
    fields.set(part.fieldname, values);
  }
  if (file === undefined) {
    throw validationError(['file']);
  }

  const metadata: unknown = {
    project_id: requiredField(fields, 'project_id'),
    topic_id: nullableField(fields, 'topic_id'),
    type: requiredField(fields, 'type'),
    title: requiredField(fields, 'title'),
    summary: nullableField(fields, 'summary'),
    keywords: (fields.get('keywords') ?? []).map((value) => value.trim()),
    sensitivity_level: optionalField(fields, 'sensitivity_level') ?? 'internal',
  };
  if (!Value.Check(MemoryUploadMetadataSchema, metadata)) {
    const errors = [...Value.Errors(MemoryUploadMetadataSchema, metadata)];
    throw validationError(
      errors.map((error) => (error.path.length > 0 ? error.path : 'request')),
    );
  }
  return { metadata, ...file };
}

function multipartLimits(maxUploadBytes: number) {
  return {
    fieldNameSize: 64,
    fieldSize: 64 * 1024,
    fields: 256,
    files: 1,
    parts: 257,
    fileSize: maxUploadBytes,
    headerPairs: 128,
  };
}

function requiredField(fields: ReadonlyMap<string, string[]>, name: string): string {
  const value = optionalField(fields, name);
  if (value === undefined) {
    throw validationError([name]);
  }
  return value;
}

function optionalField(
  fields: ReadonlyMap<string, string[]>,
  name: string,
): string | undefined {
  return fields.get(name)?.[0]?.trim();
}

function nullableField(fields: ReadonlyMap<string, string[]>, name: string): string | null {
  const value = optionalField(fields, name);
  return value === undefined || value.length === 0 ? null : value;
}

function normalizedFileName(value: string): string {
  const normalized = value.replaceAll('\\', '/').split('/').at(-1)?.trim() ?? '';
  if (normalized.length === 0 || normalized.includes('\0')) {
    throw validationError(['file']);
  }
  return normalized;
}

function validationError(fields: string[]): DirectorProtocolError {
  return new DirectorProtocolError(
    400,
    'validation_error',
    'The request does not match the Director API contract.',
    false,
    { fields },
  );
}

function fastifyErrorCode(error: unknown): string | undefined {
  if (typeof error !== 'object' || error === null || !('code' in error)) {
    return undefined;
  }
  return typeof error.code === 'string' ? error.code : undefined;
}

function validationFields(error: unknown): string[] | undefined {
  if (typeof error !== 'object' || error === null || !('validation' in error)) {
    return undefined;
  }
  const validation = error.validation;
  if (!Array.isArray(validation)) {
    return undefined;
  }
  return validation.map((item: unknown) => {
    if (typeof item !== 'object' || item === null) {
      return 'request';
    }
    const instancePath = 'instancePath' in item ? item.instancePath : undefined;
    if (typeof instancePath === 'string' && instancePath.length > 0) {
      return instancePath;
    }
    const schemaPath = 'schemaPath' in item ? item.schemaPath : undefined;
    return typeof schemaPath === 'string' ? schemaPath : 'request';
  });
}
