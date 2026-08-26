import { timingSafeEqual } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { createServer, type Server } from 'node:https';
import type { IncomingMessage, ServerResponse } from 'node:http';
import type { PeerCertificate, TLSSocket } from 'node:tls';

import type { InferenceConfig } from './config.js';
import { parseInferenceRequest, ProtocolError } from './protocol.js';
import { LlamaClient, UpstreamError } from './upstream.js';

interface CachedResponse {
  statusCode: number;
  payload: Record<string, unknown>;
}

export async function createInferenceServer(config: InferenceConfig): Promise<Server> {
  const [cert, key, ca, tokenRaw] = await Promise.all([
    readFile(config.tlsCertPath),
    readFile(config.tlsKeyPath),
    readFile(config.tlsCaPath),
    readFile(config.tokenFile, 'utf8'),
  ]);
  const token = tokenRaw.trim();
  if (token.length < 32 || token.length > 4096 || /\s/.test(token)) {
    throw new Error('Inference bearer token is invalid.');
  }
  const client = new LlamaClient({
    origin: config.upstreamOrigin,
    model: config.model,
    maxPromptCharacters: config.maxPromptCharacters,
    maxOutputTokens: config.maxOutputTokens,
    timeoutMs: config.upstreamTimeoutMs,
  });
  const completed = new Map<string, CachedResponse>();
  return createServer(
    { cert, key, ca, requestCert: true, rejectUnauthorized: true, minVersion: 'TLSv1.3' },
    (request, response) => {
      void handleRequest(request, response, config, token, client, completed);
    },
  );
}

async function handleRequest(
  request: IncomingMessage,
  response: ServerResponse,
  config: InferenceConfig,
  token: string,
  client: LlamaClient,
  completed: Map<string, CachedResponse>,
): Promise<void> {
  response.setHeader('cache-control', 'no-store');
  response.setHeader('content-type', 'application/json; charset=utf-8');
  if (!approvedPeer((request.socket as TLSSocket).getPeerCertificate(), config.allowedPeerCommonName)) {
    return send(response, 403, { error: { code: 'peer_not_allowed' } });
  }
  if (request.method === 'GET' && request.url === '/health/live') {
    return send(response, 200, { status: 'live' });
  }
  if (request.method === 'GET' && request.url === '/health/ready') {
    const ready = await client.ready();
    return send(response, ready ? 200 : 503, { status: ready ? 'ready' : 'not_ready' });
  }
  if (request.method !== 'POST' || request.url !== '/v1/generate') {
    return send(response, 404, { error: { code: 'not_found' } });
  }
  if (!authorized(request.headers.authorization, token)) {
    return send(response, 401, { error: { code: 'unauthorized' } });
  }
  const controller = new AbortController();
  request.once('aborted', () => controller.abort());
  try {
    const body = await readJsonBody(request, config.maxRequestBytes);
    const parsed = parseInferenceRequest(body, config.model);
    const cached = completed.get(parsed.agent_run_id);
    if (cached !== undefined) return send(response, cached.statusCode, cached.payload);
    const result = await client.generate(parsed, controller.signal);
    const payload = {
      protocol_version: '1.0',
      agent_run_id: parsed.agent_run_id,
      model: parsed.model,
      provider_request_id: result.providerRequestId,
      content: result.content,
      content_type: 'text/markdown',
      finish_reason: result.finishReason,
      ...(result.usage === undefined ? {} : { usage: result.usage }),
      output_summary: null,
    };
    completed.set(parsed.agent_run_id, { statusCode: 200, payload });
    if (completed.size > 256) completed.delete(completed.keys().next().value as string);
    return send(response, 200, payload);
  } catch (error) {
    if (error instanceof ProtocolError || error instanceof UpstreamError) {
      return send(response, error.statusCode, { error: { code: error.code } });
    }
    return send(response, 500, { error: { code: 'internal_error' } });
  }
}

function approvedPeer(certificate: PeerCertificate, expectedCommonName: string): boolean {
  return certificate.subject?.CN === expectedCommonName;
}

function authorized(header: string | undefined, token: string): boolean {
  if (header === undefined || !header.startsWith('Bearer ')) return false;
  const candidate = Buffer.from(header.slice(7));
  const expected = Buffer.from(token);
  return candidate.length === expected.length && timingSafeEqual(candidate, expected);
}

async function readJsonBody(request: IncomingMessage, maximumBytes: number): Promise<unknown> {
  const contentType = request.headers['content-type'];
  if (typeof contentType !== 'string' || !contentType.toLowerCase().startsWith('application/json')) {
    throw new ProtocolError('Content-Type must be application/json.', 415, 'unsupported_media_type');
  }
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of request) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk as Uint8Array);
    size += buffer.length;
    if (size > maximumBytes) throw new ProtocolError('Request is too large.', 413, 'request_too_large');
    chunks.push(buffer);
  }
  try {
    return JSON.parse(Buffer.concat(chunks).toString('utf8')) as unknown;
  } catch {
    throw new ProtocolError('Request body is not valid JSON.');
  }
}

function send(response: ServerResponse, statusCode: number, payload: Record<string, unknown>): void {
  if (response.writableEnded) return;
  response.statusCode = statusCode;
  response.end(JSON.stringify(payload));
}
