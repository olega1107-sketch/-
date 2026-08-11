#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/dirizhor-mtls.XXXXXX")"
server_pid=""

cleanup() {
  if [[ -n "$server_pid" ]]; then
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi
  rm -rf "$work_dir"
}
trap cleanup EXIT INT TERM

openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 1 \
  -subj '/CN=Dirizhor ephemeral smoke CA' \
  -keyout "$work_dir/ca.key" \
  -out "$work_dir/ca.crt" >/dev/null 2>&1

run_direction() {
  local label="$1"
  local server_identity="$2"
  local client_identity="$3"
  local port="$4"
  local prefix="$work_dir/$label"

  openssl req -new -newkey rsa:2048 -nodes -sha256 \
    -subj "/CN=$server_identity" \
    -keyout "$prefix-server.key" \
    -out "$prefix-server.csr" >/dev/null 2>&1
  chmod 0600 "$prefix-server.key"
  printf '%s\n' \
    'basicConstraints=critical,CA:FALSE' \
    'keyUsage=critical,digitalSignature,keyEncipherment' \
    'extendedKeyUsage=serverAuth' \
    'subjectAltName=DNS:localhost' > "$prefix-server.ext"
  openssl x509 -req -sha256 -days 1 \
    -in "$prefix-server.csr" \
    -CA "$work_dir/ca.crt" \
    -CAkey "$work_dir/ca.key" \
    -CAcreateserial \
    -extfile "$prefix-server.ext" \
    -out "$prefix-server.crt" >/dev/null 2>&1

  openssl req -new -newkey rsa:2048 -nodes -sha256 \
    -subj "/CN=$client_identity" \
    -keyout "$prefix-client.key" \
    -out "$prefix-client.csr" >/dev/null 2>&1
  chmod 0600 "$prefix-client.key"
  printf '%s\n' \
    'basicConstraints=critical,CA:FALSE' \
    'keyUsage=critical,digitalSignature,keyEncipherment' \
    'extendedKeyUsage=clientAuth' > "$prefix-client.ext"
  openssl x509 -req -sha256 -days 1 \
    -in "$prefix-client.csr" \
    -CA "$work_dir/ca.crt" \
    -CAkey "$work_dir/ca.key" \
    -CAcreateserial \
    -extfile "$prefix-client.ext" \
    -out "$prefix-client.crt" >/dev/null 2>&1

  openssl verify -purpose sslserver -CAfile "$work_dir/ca.crt" \
    "$prefix-server.crt" >/dev/null
  openssl verify -purpose sslclient -CAfile "$work_dir/ca.crt" \
    "$prefix-client.crt" >/dev/null

  openssl s_server -quiet -www -Verify 1 \
    -accept "$port" \
    -cert "$prefix-server.crt" \
    -key "$prefix-server.key" \
    -CAfile "$work_dir/ca.crt" \
    >"$prefix-server.log" 2>&1 &
  server_pid="$!"

  local ready=false
  for _ in {1..30}; do
    if curl --silent --show-error --fail \
      --connect-timeout 1 --max-time 2 \
      --cacert "$work_dir/ca.crt" \
      --cert "$prefix-client.crt" \
      --key "$prefix-client.key" \
      "https://localhost:$port/" >/dev/null 2>&1; then
      ready=true
      break
    fi
    sleep 0.1
  done
  if [[ "$ready" != true ]]; then
    printf 'mTLS smoke failed for %s\n' "$label" >&2
    tail -20 "$prefix-server.log" >&2 || true
    return 1
  fi

  if curl --silent --fail \
    --connect-timeout 1 --max-time 2 \
    --cacert "$work_dir/ca.crt" \
    "https://localhost:$port/" >/dev/null 2>&1; then
    printf 'mTLS smoke unexpectedly accepted a request without client certificate: %s\n' \
      "$label" >&2
    return 1
  fi

  kill "$server_pid"
  wait "$server_pid" 2>/dev/null || true
  server_pid=""
  printf 'mTLS direction verified: %s (%s -> %s)\n' \
    "$label" "$client_identity" "$server_identity"
}

base_port="${MTLS_SMOKE_PORT:-$((20000 + RANDOM % 20000))}"
run_direction 'director-to-gateway' 'gateway.internal' 'director-api' "$base_port"
run_direction 'gateway-to-director' 'director.internal' 'agent-gateway' "$((base_port + 1))"
env \
  MTLS_PREFLIGHT_MIN_VALIDITY_SECONDS=60 \
  DIRECTOR_BASE_URL=https://localhost \
  GATEWAY_BASE_URL=https://localhost \
  DIRECTOR_TLS_CERT_PATH="$work_dir/gateway-to-director-server.crt" \
  DIRECTOR_TLS_KEY_PATH="$work_dir/gateway-to-director-server.key" \
  DIRECTOR_TLS_CA_PATH="$work_dir/ca.crt" \
  DIRECTOR_ALLOWED_PEER_CNS=agent-gateway \
  DIRECTOR_GATEWAY_CLIENT_CERT_PATH="$work_dir/director-to-gateway-client.crt" \
  DIRECTOR_GATEWAY_CLIENT_KEY_PATH="$work_dir/director-to-gateway-client.key" \
  DIRECTOR_GATEWAY_CA_PATH="$work_dir/ca.crt" \
  GATEWAY_TLS_CERT_PATH="$work_dir/director-to-gateway-server.crt" \
  GATEWAY_TLS_KEY_PATH="$work_dir/director-to-gateway-server.key" \
  GATEWAY_TLS_CA_PATH="$work_dir/ca.crt" \
  GATEWAY_ALLOWED_PEER_CNS=director-api \
  GATEWAY_DIRECTOR_CLIENT_CERT_PATH="$work_dir/gateway-to-director-client.crt" \
  GATEWAY_DIRECTOR_CLIENT_KEY_PATH="$work_dir/gateway-to-director-client.key" \
  GATEWAY_DIRECTOR_CA_PATH="$work_dir/ca.crt" \
  node "$script_dir/certificate-preflight.mjs" >/dev/null
printf 'Certificate profile preflight passed.\n'
printf 'Ephemeral two-way mTLS smoke passed.\n'
