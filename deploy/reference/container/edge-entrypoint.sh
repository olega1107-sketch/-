#!/bin/sh
set -eu
umask 077

fail() {
  printf 'Dirizhor edge startup failed: %s\n' "$1" >&2
  exit 1
}

require_value() {
  [ -n "$2" ] || fail "$1 is required."
}

safe_host() {
  case "$2" in
    ''|.*|*.|*..*|*[!A-Za-z0-9._-]*) fail "$1 is not a safe host value." ;;
  esac
}

safe_port() {
  case "$2" in
    ''|*[!0-9]*) fail "$1 must be an integer." ;;
  esac
  [ "$2" -ge "$3" ] && [ "$2" -le 65535 ] || fail "$1 is outside the allowed range."
}

require_value DIRECTOR_PUBLIC_HOST "${DIRECTOR_PUBLIC_HOST:-}"
require_value PUBLIC_LISTEN_PORT "${PUBLIC_LISTEN_PORT:-}"
require_value DIRECTOR_PUBLIC_PORT "${DIRECTOR_PUBLIC_PORT:-}"
require_value DIRECTOR_UPSTREAM_HOST "${DIRECTOR_UPSTREAM_HOST:-}"
require_value DIRECTOR_UPSTREAM_PORT "${DIRECTOR_UPSTREAM_PORT:-}"
require_value DIRECTOR_UPSTREAM_TLS_NAME "${DIRECTOR_UPSTREAM_TLS_NAME:-}"
require_value DIRECTOR_MAX_BODY_SIZE "${DIRECTOR_MAX_BODY_SIZE:-}"

safe_host DIRECTOR_PUBLIC_HOST "$DIRECTOR_PUBLIC_HOST"
safe_host DIRECTOR_UPSTREAM_HOST "$DIRECTOR_UPSTREAM_HOST"
safe_host DIRECTOR_UPSTREAM_TLS_NAME "$DIRECTOR_UPSTREAM_TLS_NAME"
safe_port PUBLIC_LISTEN_PORT "$PUBLIC_LISTEN_PORT" 1024
safe_port DIRECTOR_PUBLIC_PORT "$DIRECTOR_PUBLIC_PORT" 1
safe_port DIRECTOR_UPSTREAM_PORT "$DIRECTOR_UPSTREAM_PORT" 1
case "$DIRECTOR_MAX_BODY_SIZE" in
  *[!0-9kKmMgG]*) fail 'DIRECTOR_MAX_BODY_SIZE contains unsupported characters.' ;;
esac

for secret in \
  /run/secrets/public-tls.crt \
  /run/secrets/public-tls.key \
  /run/secrets/director-upstream-ca.crt
do
  [ -f "$secret" ] && [ -r "$secret" ] || fail 'A required TLS file is unavailable.'
done

key_mode="$(stat -L -c '%a' /run/secrets/public-tls.key 2>/dev/null)" || \
  fail 'Public TLS key permissions could not be inspected.'
case "$key_mode" in
  400|440|600|640) ;;
  *) fail 'Public TLS key permissions must be 0400, 0440, 0600, or 0640.' ;;
esac

runtime_directory=/tmp/dirizhor-nginx
rm -rf "$runtime_directory"
mkdir -m 0700 "$runtime_directory"
mkdir -m 0700 "$runtime_directory/client-body" "$runtime_directory/proxy"
cp /opt/dirizhor/nginx/security-headers.conf "$runtime_directory/security-headers.conf"

export DIRIZHOR_NGINX_INCLUDE_DIR="$runtime_directory"
envsubst '${DIRECTOR_PUBLIC_HOST} ${PUBLIC_LISTEN_PORT} ${DIRECTOR_UPSTREAM_HOST} ${DIRECTOR_UPSTREAM_PORT} ${DIRECTOR_MAX_BODY_SIZE} ${DIRIZHOR_NGINX_INCLUDE_DIR}' \
  < /opt/dirizhor/nginx/nginx.conf.template \
  > "$runtime_directory/nginx.conf"
envsubst '${DIRECTOR_PUBLIC_HOST} ${DIRECTOR_PUBLIC_PORT} ${DIRECTOR_UPSTREAM_TLS_NAME}' \
  < /opt/dirizhor/nginx/director-proxy.conf.template \
  > "$runtime_directory/director-proxy.conf"

if grep -q '\${' "$runtime_directory/nginx.conf" "$runtime_directory/director-proxy.conf"; then
  fail 'Rendered Nginx configuration still contains a template variable.'
fi

nginx -t -q -c "$runtime_directory/nginx.conf"
exec nginx -c "$runtime_directory/nginx.conf" -g 'daemon off;'
