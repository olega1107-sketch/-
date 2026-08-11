# syntax=docker/dockerfile:1.7

ARG NODE_BUILD_IMAGE
ARG NODE_RUNTIME_IMAGE

FROM ${NODE_BUILD_IMAGE} AS build
ARG NODE_BUILD_IMAGE
ARG NODE_RUNTIME_IMAGE
ARG PNPM_VERSION
RUN node -e 'const p=/^[^@\s]+@sha256:[0-9a-f]{64}$/; for (const n of ["NODE_BUILD_IMAGE", "NODE_RUNTIME_IMAGE"]) if (!p.test(process.env[n] || "")) process.exit(1)' && \
    test -n "${PNPM_VERSION}" && test "$(pnpm --version)" = "${PNPM_VERSION}"

WORKDIR /workspace/gateway/reference
COPY gateway/reference/package.json gateway/reference/pnpm-lock.yaml gateway/reference/pnpm-workspace.yaml ./
RUN --mount=type=cache,target=/pnpm/store,sharing=locked \
    pnpm config set store-dir /pnpm/store && \
    pnpm fetch --frozen-lockfile

COPY gateway/reference/ ./
RUN --mount=type=cache,target=/pnpm/store,sharing=locked \
    pnpm install --frozen-lockfile --offline --ignore-scripts && \
    pnpm build && \
    pnpm prune --prod

FROM ${NODE_RUNTIME_IMAGE} AS runtime
ENV NODE_ENV=production
WORKDIR /app/gateway/reference
COPY --from=build --chown=10001:10001 /workspace/gateway/reference/package.json ./package.json
COPY --from=build --chown=10001:10001 /workspace/gateway/reference/node_modules/ ./node_modules/
COPY --from=build --chown=10001:10001 /workspace/gateway/reference/dist/ ./dist/

USER 10001:10001
EXPOSE 8443
STOPSIGNAL SIGTERM
ENTRYPOINT []
CMD ["node", "dist/main.js"]
