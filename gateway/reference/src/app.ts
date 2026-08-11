import { randomUUID } from 'node:crypto';
import type { ServerOptions as HttpsServerOptions } from 'node:https';

import type { TypeBoxTypeProvider } from '@fastify/type-provider-typebox';
import { Type } from '@sinclair/typebox';
import Fastify, { type FastifyRequest } from 'fastify';

import { DirectorClientError, GatewayProtocolError } from './errors.js';
import type { GatewayService } from './gateway-service.js';
import type { ServiceAuthenticator } from './ports.js';
import {
  AgentCancellationReceiptSchema,
  AgentCancellationRequestSchema,
  AgentExecutionReceiptSchema,
  AgentExecutionRequestSchema,
  AgentRunIdParamsSchema,
  CancelHeadersSchema,
  ExecuteHeadersSchema,
  ProtocolErrorResponseSchema,
} from './protocol.js';

export interface GatewayAppOptions {
  service: GatewayService;
  authenticator: ServiceAuthenticator;
  https?: HttpsServerOptions | null;
  readiness?: () => Promise<void>;
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
const HealthStatusSchema = Type.Object(
  { status: Type.Union([Type.Literal('ok'), Type.Literal('unavailable')]) },
  { additionalProperties: false },
);

export function buildGatewayApp(options: GatewayAppOptions) {
  const app = Fastify({
    logger: false,
    https: options.https ?? null,
  }).withTypeProvider<TypeBoxTypeProvider>();

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

  app.post(
    `/internal/v1/agent-runs/${agentRunRouteParameter}::execute`,
    {
      schema: {
        params: AgentRunIdParamsSchema,
        headers: ExecuteHeadersSchema,
        body: AgentExecutionRequestSchema,
        response: { 202: AgentExecutionReceiptSchema, ...errorResponses },
      },
      preHandler: async (request) => authenticate(options.authenticator, request),
    },
    async (request, reply) => {
      const requestId = requestIdFor(request);
      const receipt = await options.service.execute({
        agentRunId: request.params.agent_run_id,
        idempotencyKey: request.headers['idempotency-key'],
        capability: request.headers['x-agent-capability'],
        requestId,
        request: request.body,
      });
      return reply.header('x-request-id', requestId).status(202).send(receipt);
    },
  );

  app.post(
    `/internal/v1/agent-runs/${agentRunRouteParameter}::cancel`,
    {
      schema: {
        params: AgentRunIdParamsSchema,
        headers: CancelHeadersSchema,
        body: AgentCancellationRequestSchema,
        response: { 202: AgentCancellationReceiptSchema, ...errorResponses },
      },
      preHandler: async (request) => authenticate(options.authenticator, request),
    },
    async (request, reply) => {
      const requestId = requestIdFor(request);
      const receipt = await options.service.cancel({
        agentRunId: request.params.agent_run_id,
        idempotencyKey: request.headers['idempotency-key'],
        requestId,
        request: request.body,
      });
      return reply.header('x-request-id', requestId).status(202).send(receipt);
    },
  );

  app.setErrorHandler((error, request, reply) => {
    const requestId = requestIdFor(request);
    const mapped = mapError(error);
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

function mapError(error: unknown): MappedError {
  if (error instanceof GatewayProtocolError) {
    return {
      statusCode: error.statusCode,
      code: error.code,
      message: error.message,
      retryable: error.retryable,
      details: error.details,
    };
  }
  if (error instanceof DirectorClientError) {
    return {
      statusCode: error.statusCode ?? 503,
      code: 'unavailable',
      message: 'A required internal service is unavailable.',
      retryable: error.retryable,
      details:
        error.retryAfterSeconds === undefined
          ? {}
          : { retry_after_seconds: error.retryAfterSeconds },
    };
  }
  const fields = validationFields(error);
  if (fields !== undefined) {
    return {
      statusCode: 400,
      code: 'validation_error',
      message: 'The request does not match the gateway protocol.',
      retryable: false,
      details: { fields },
    };
  }
  return {
    statusCode: 500,
    code: 'internal_error',
    message: 'The gateway could not process the request.',
    retryable: false,
    details: {},
  };
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
