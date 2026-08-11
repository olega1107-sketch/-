export const userSessionCookieName = '__Host-dirizhor_session';
export const oidcTransactionCookieName = '__Host-dirizhor_oidc';

export const protectedAuthenticationCookieOptions = {
  path: '/',
  httpOnly: true,
  secure: true,
  sameSite: 'lax',
  priority: 'high',
} as const;
