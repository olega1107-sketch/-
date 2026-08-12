# Reference UI

Responsive confirmation and decision-history UI for the Director API. The module is a separate
Vite client and never reads the database, document store, or AI providers
directly.

## Implemented flow

- corporate OIDC redirect through `GET /api/v1/auth/oidc/start`;
- Director session through a Secure HttpOnly cookie that client JavaScript does
  not read;
- optional local session login through `POST /api/v1/auth/sessions`, with its
  fallback bearer kept only in `sessionStorage`;
- readable project selection through `GET /api/v1/projects`;
- pending/completed/rejected confirmation views;
- opaque-cursor pagination;
- confirmation details without internal `frozen_payload`;
- approve/reject dialogs and automatic queue refresh;
- decision creation in the pilot-safe `draft` or `proposed` states;
- explicit relationship source rows for memory objects, tasks, agent runs,
  decisions and open questions;
- decision lookup by ID and a metadata-only provenance view with related memory
  objects, agent runs, exact frozen document versions and audit events;
- responsive desktop and mobile layouts.

## Development

```bash
pnpm install
pnpm dev
```

The dev server listens on `http://127.0.0.1:4173` and proxies `/api` to
`http://127.0.0.1:8444`. Override the target with
`DIRECTOR_UI_API_TARGET`. For static development authentication only, provide
`VITE_DIRECTOR_STATIC_TOKEN`. Set `VITE_DIRECTOR_LOCAL_LOGIN_ENABLED=true` only
when the backend local password endpoint is intentionally enabled. Production
deployments should use the same-origin Director OIDC/session-cookie boundary.

Run `node scripts/mock-api.mjs` in another terminal for an isolated visual
preview. The mock server is development-only and is not included in `dist`.

## Verification

```bash
pnpm check
pnpm test
pnpm build
```
