import { Type, type Static } from '@sinclair/typebox';

import { TimestampSchema, UuidSchema } from './protocol.js';

export const SessionCreateSchema = Type.Object(
  {
    login: Type.String({ minLength: 1, maxLength: 256 }),
    password: Type.String({ minLength: 1, maxLength: 1024 }),
  },
  { additionalProperties: false },
);
export type SessionCreate = Static<typeof SessionCreateSchema>;

export const UserSessionSchema = Type.Object(
  {
    id: UuidSchema,
    user_id: UuidSchema,
    authentication_method: Type.String({ minLength: 1, maxLength: 256 }),
    created_at: TimestampSchema,
    expires_at: TimestampSchema,
  },
  { additionalProperties: false },
);
export type UserSession = Static<typeof UserSessionSchema>;

export const IssuedUserSessionSchema = Type.Object(
  {
    access_token: Type.String({ pattern: '^[A-Za-z0-9_-]{43}$' }),
    token_type: Type.Literal('Bearer'),
    session: UserSessionSchema,
  },
  { additionalProperties: false },
);
export type IssuedUserSession = Static<typeof IssuedUserSessionSchema>;
