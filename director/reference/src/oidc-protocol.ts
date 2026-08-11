import { Type, type Static } from '@sinclair/typebox';

import { UuidSchema } from './protocol.js';

export const BrowserAuthenticationHeadersSchema = Type.Object(
  {
    'x-request-id': Type.Optional(UuidSchema),
  },
  { additionalProperties: true },
);

export const OidcCallbackQuerySchema = Type.Object(
  {
    code: Type.Optional(Type.String({ minLength: 1, maxLength: 8192 })),
    state: Type.Optional(Type.String({ minLength: 1, maxLength: 512 })),
    error: Type.Optional(Type.String({ minLength: 1, maxLength: 256 })),
    error_description: Type.Optional(Type.String({ minLength: 1, maxLength: 2048 })),
    error_uri: Type.Optional(Type.String({ minLength: 1, maxLength: 2048 })),
    iss: Type.Optional(Type.String({ minLength: 1, maxLength: 2048 })),
    session_state: Type.Optional(Type.String({ minLength: 1, maxLength: 2048 })),
  },
  { additionalProperties: false },
);
export type OidcCallbackQuery = Static<typeof OidcCallbackQuerySchema>;

export const OidcLogoutResponseSchema = Type.Object(
  {
    logout_url: Type.Union([
      Type.Null(),
      Type.String({ format: 'uri', maxLength: 4096 }),
    ]),
  },
  { additionalProperties: false },
);
