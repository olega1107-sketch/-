#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/../.." && pwd)"
export PATH="${REPO_ROOT}/.tools/bin:${PATH}"

LOCAL_ENV_FILE="${1:-${SCRIPT_DIR}/environments/pilot/.env.local}"

if [[ -f "${LOCAL_ENV_FILE}" ]]; then
  token_line="$(grep -m 1 '^DIGITALOCEAN_TOKEN=' "${LOCAL_ENV_FILE}" || true)"
  if [[ -n "${token_line}" ]]; then
    token_value="${token_line#DIGITALOCEAN_TOKEN=}"
    if [[ "${token_value}" =~ (dop_v1_[A-Za-z0-9_-]+) ]]; then
      export DIGITALOCEAN_TOKEN="${BASH_REMATCH[1]}"
    else
      export DIGITALOCEAN_TOKEN="${token_value}"
    fi
  fi
fi

if [[ -z "${DIGITALOCEAN_TOKEN:-}" ]]; then
  echo "DIGITALOCEAN_TOKEN is not set. Add it locally in ${LOCAL_ENV_FILE}." >&2
  exit 1
fi

export DIGITALOCEAN_ACCESS_TOKEN="${DIGITALOCEAN_TOKEN}"
