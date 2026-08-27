const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const opaquePattern = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$/;

export interface InferenceRequest {
  protocol_version: '1.0';
  agent_run_id: string;
  project_id: string;
  origin_request_id: string;
  agent_type: string;
  model: string;
  purpose: string;
  instructions: string;
  deadline_at: string;
  context: {
    context_set_hash: string;
    max_sensitivity_level: string;
    items: ContextItem[];
  };
}

interface ContextItem {
  position: number;
  file_name: string;
  media_type: string;
  size_bytes: number;
  content_encoding: string;
  content: string;
  content_hash: string;
  sensitivity_level: string;
  access_reason: string;
}

export class ProtocolError extends Error {
  constructor(
    message: string,
    readonly statusCode = 400,
    readonly code = 'invalid_request',
  ) {
    super(message);
  }
}

export function parseInferenceRequest(value: unknown, approvedModel: string): InferenceRequest {
  const request = object(value, 'request');
  exactKeys(request, [
    'protocol_version', 'agent_run_id', 'project_id', 'origin_request_id', 'agent_type',
    'model', 'purpose', 'instructions', 'deadline_at', 'context',
  ], 'request');
  const context = object(request.context, 'context');
  exactKeys(context, ['context_set_hash', 'max_sensitivity_level', 'items'], 'context');
  if (!Array.isArray(context.items) || context.items.length === 0 || context.items.length > 100) {
    throw new ProtocolError('context.items must contain from 1 through 100 items.');
  }
  const model = text(request.model, 'model', 1, 128);
  if (model !== approvedModel) throw new ProtocolError('The requested model is not approved.', 403, 'model_not_allowed');
  const deadlineAt = text(request.deadline_at, 'deadline_at', 20, 64);
  const deadline = Date.parse(deadlineAt);
  if (!Number.isFinite(deadline) || deadline <= Date.now()) {
    throw new ProtocolError('deadline_at must be a future RFC 3339 timestamp.');
  }
  return {
    protocol_version: literal(request.protocol_version, '1.0', 'protocol_version'),
    agent_run_id: pattern(request.agent_run_id, uuidPattern, 'agent_run_id'),
    project_id: pattern(request.project_id, uuidPattern, 'project_id'),
    origin_request_id: pattern(request.origin_request_id, opaquePattern, 'origin_request_id'),
    agent_type: pattern(request.agent_type, opaquePattern, 'agent_type'),
    model,
    purpose: text(request.purpose, 'purpose', 1, 2048),
    instructions: text(request.instructions, 'instructions', 1, 32_768),
    deadline_at: new Date(deadline).toISOString(),
    context: {
      context_set_hash: sha256(context.context_set_hash, 'context_set_hash'),
      max_sensitivity_level: pattern(context.max_sensitivity_level, opaquePattern, 'max_sensitivity_level'),
      items: context.items.map((item, index) => parseContextItem(item, index)),
    },
  };
}

function parseContextItem(value: unknown, index: number): ContextItem {
  const item = object(value, `context.items[${index}]`);
  exactKeys(item, [
    'position', 'file_name', 'media_type', 'size_bytes', 'content_encoding', 'content',
    'content_hash', 'sensitivity_level', 'access_reason',
  ], `context.items[${index}]`);
  const position = integer(item.position, `context.items[${index}].position`, 1, 100);
  if (position !== index + 1) throw new ProtocolError('Context positions must be contiguous and ordered.');
  return {
    position,
    file_name: text(item.file_name, 'file_name', 1, 512),
    media_type: text(item.media_type, 'media_type', 1, 128),
    size_bytes: integer(item.size_bytes, 'size_bytes', 0, 50 * 1024 * 1024),
    content_encoding: literal(item.content_encoding, 'utf-8', 'content_encoding'),
    content: text(item.content, 'content', 0, 5 * 1024 * 1024),
    content_hash: sha256(item.content_hash, 'content_hash'),
    sensitivity_level: pattern(item.sensitivity_level, opaquePattern, 'sensitivity_level'),
    access_reason: text(item.access_reason, 'access_reason', 1, 2048),
  };
}

function object(value: unknown, name: string): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new ProtocolError(`${name} must be an object.`);
  }
  return value as Record<string, unknown>;
}

function exactKeys(value: Record<string, unknown>, keys: string[], name: string): void {
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw new ProtocolError(`${name} contains unsupported or missing fields.`);
  }
}

function text(value: unknown, name: string, minimum: number, maximum: number): string {
  if (typeof value !== 'string' || value.length < minimum || value.length > maximum || value.includes('\0')) {
    throw new ProtocolError(`${name} has an invalid length or type.`);
  }
  return value;
}

function pattern(value: unknown, pattern_: RegExp, name: string): string {
  const parsed = text(value, name, 1, 256);
  if (!pattern_.test(parsed)) throw new ProtocolError(`${name} has an invalid format.`);
  return parsed;
}

function sha256(value: unknown, name: string): string {
  if (typeof value !== 'string' || !/^sha256:[0-9a-f]{64}$/i.test(value)) {
    throw new ProtocolError(`${name} must be a SHA-256 digest.`);
  }
  return value.toLowerCase();
}

function integer(value: unknown, name: string, minimum: number, maximum: number): number {
  if (!Number.isSafeInteger(value) || (value as number) < minimum || (value as number) > maximum) {
    throw new ProtocolError(`${name} must be an integer from ${minimum} through ${maximum}.`);
  }
  return value as number;
}

function literal<T extends string>(value: unknown, expected: T, name: string): T {
  if (value !== expected) throw new ProtocolError(`${name} must be ${expected}.`);
  return expected;
}
