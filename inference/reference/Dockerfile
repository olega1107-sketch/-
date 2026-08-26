# syntax=docker/dockerfile:1.7

ARG NODE_BUILD_IMAGE
ARG NODE_RUNTIME_IMAGE

FROM ${NODE_BUILD_IMAGE} AS build
ARG NODE_BUILD_IMAGE
ARG NODE_RUNTIME_IMAGE
ARG PNPM_VERSION
RUN node -e 'const p=/^[^@\s]+@sha256:[0-9a-f]{64}$/; for (const n of ["NODE_BUILD_IMAGE", "NODE_RUNTIME_IMAGE"]) if (!p.test(process.env[n] || "")) process.exit(1)' && \
    test -n "${PNPM_VERSION}" && test "$(pnpm --version)" = "${PNPM_VERSION}"

WORKDIR /workspace/inference/reference
COPY inference/reference/package.json inference/reference/pnpm-lock.yaml inference/reference/pnpm-workspace.yaml ./
RUN --mount=type=cache,target=/pnpm/store,sharing=locked \
    pnpm config set store-dir /pnpm/store && \
    pnpm fetch --frozen-lockfile

COPY inference/reference/ ./
RUN --mount=type=cache,target=/pnpm/store,sharing=locked \
    pnpm install --frozen-lockfile --offline --ignore-scripts && \
    pnpm build

FROM ${NODE_RUNTIME_IMAGE} AS runtime
ENV NODE_ENV=production
RUN apk add --no-cache --upgrade libcrypto3=3.5.8-r0 libssl3=3.5.8-r0 && \
    rm -rf /usr/local/lib/node_modules/npm && \
    rm -f /usr/local/bin/npm /usr/local/bin/npx && \
    node --version >/dev/null
WORKDIR /app/inference/reference
COPY --from=build --chown=10001:10001 /workspace/inference/reference/package.json ./package.json
COPY --from=build --chown=10001:10001 /workspace/inference/reference/dist/ ./dist/

USER 10001:10001
EXPOSE 8443
STOPSIGNAL SIGTERM
ENTRYPOINT []
CMD ["node", "dist/main.js"]
