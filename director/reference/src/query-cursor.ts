import { DirectorProtocolError } from './errors.js';

interface CursorEnvelope {
  version: 1;
  scope: string;
  position: unknown;
}

const maxCursorLength = 4096;

export function encodeQueryCursor(scope: string, position: unknown): string {
  const envelope: CursorEnvelope = { version: 1, scope, position };
  return Buffer.from(JSON.stringify(envelope), 'utf8').toString('base64url');
}

export function decodeQueryCursor<T>(
  cursor: string,
  expectedScope: string,
  validatePosition: (value: unknown) => value is T,
): T {
  if (
    cursor.length > maxCursorLength ||
    !/^[A-Za-z0-9_-]+$/.test(cursor)
  ) {
    throw invalidCursor();
  }
  try {
    const value: unknown = JSON.parse(Buffer.from(cursor, 'base64url').toString('utf8'));
    if (!isCursorEnvelope(value) || value.scope !== expectedScope) {
      throw invalidCursor();
    }
    if (!validatePosition(value.position)) {
      throw invalidCursor();
    }
    return value.position;
  } catch (error) {
    if (error instanceof DirectorProtocolError) {
      throw error;
    }
    throw invalidCursor();
  }
}

function isCursorEnvelope(value: unknown): value is CursorEnvelope {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return false;
  }
  const record = value as Record<string, unknown>;
  return (
    Object.keys(record).length === 3 &&
    record.version === 1 &&
    typeof record.scope === 'string' &&
    'position' in record
  );
}

function invalidCursor(): DirectorProtocolError {
  return new DirectorProtocolError(
    400,
    'validation_error',
    'The pagination cursor is invalid for this request.',
  );
}
