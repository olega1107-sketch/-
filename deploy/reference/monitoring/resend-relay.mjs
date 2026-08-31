import { createHash, timingSafeEqual } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { createServer } from 'node:http';

const resendUrl = 'https://api.resend.com/emails';
const maxBodyBytes = 128 * 1024;

export async function createRelayConfig(environment = process.env) {
  const [webhookToken, apiKey] = await Promise.all([
    readSecret(environment.ALERT_RELAY_WEBHOOK_TOKEN_FILE, 'ALERT_RELAY_WEBHOOK_TOKEN_FILE'),
    readSecret(environment.RESEND_API_KEY_FILE, 'RESEND_API_KEY_FILE'),
  ]);
  const from = requiredEmail(environment.RESEND_FROM, 'RESEND_FROM');
  const to = requiredEmail(environment.RESEND_TO, 'RESEND_TO');
  const timeoutMs = positiveInteger(environment.REQUEST_TIMEOUT_MS ?? '8000', 'REQUEST_TIMEOUT_MS', 15_000);
  const retryDelays = parseRetryDelays(environment.RETRY_DELAYS_MS ?? '300,1200');
  return { webhookToken, apiKey, from, to, timeoutMs, retryDelays };
}

export function createRelayServer(config, dependencies = { fetch, logger: console }) {
  return createServer(async (request, response) => {
    try {
      if (request.method === 'GET' && (request.url === '/health/live' || request.url === '/health/ready')) {
        return respond(response, 200, { status: 'ok' });
      }
      if (request.method !== 'POST' || request.url !== '/v1/alerts') return respond(response, 404, { error: 'not_found' });
      if (!authorized(request.headers.authorization, config.webhookToken)) return respond(response, 401, { error: 'unauthorized' });
      const payload = validateAlertPayload(await readJson(request));
      const outgoing = composeEmail(payload, config);
      const accepted = await sendWithRetry(outgoing, config, dependencies.fetch);
      dependencies.logger.info({ event: 'resend_accepted', alert_id: outgoing.idempotencyKey, status: accepted.status, provider_id: accepted.providerId });
      return respond(response, 202, { status: 'accepted' });
    } catch (error) {
      const status = error instanceof RelayError ? error.status : 502;
      dependencies.logger.warn({ event: 'resend_rejected', status, reason: safeReason(error) });
      return respond(response, status, { error: status === 400 ? 'invalid_alert' : 'delivery_unavailable' });
    }
  });
}

export function validateAlertPayload(value) {
  if (!record(value) || !['firing', 'resolved'].includes(value.status) || !Array.isArray(value.alerts) || value.alerts.length === 0 || value.alerts.length > 20) {
    throw new RelayError(400, 'payload_shape');
  }
  const alerts = value.alerts.map((alert) => {
    if (!record(alert) || !record(alert.labels)) throw new RelayError(400, 'alert_shape');
    const alertname = safeLabel(alert.labels.alertname, 'alertname');
    const severity = safeLabel(alert.labels.severity, 'severity');
    const service = safeLabel(alert.labels.service ?? 'unknown', 'service');
    const namespace = safeLabel(alert.labels.namespace ?? 'unknown', 'namespace');
    if (severity !== 'critical') throw new RelayError(400, 'severity');
    return { alertname, severity, service, namespace, fingerprint: safeLabel(alert.fingerprint ?? alertname, 'fingerprint') };
  });
  return { status: value.status, alerts };
}

export function composeEmail(payload, config) {
  const descriptors = payload.alerts.map((alert) => `${alert.alertname}:${alert.service}:${alert.namespace}:${alert.fingerprint}`).sort();
  const idempotencyKey = `dirizhor-${createHash('sha256').update(`${payload.status}\n${descriptors.join('\n')}`).digest('hex')}`;
  const subject = `[Dirizhor][CRITICAL][${payload.status.toUpperCase()}] ${payload.alerts.map((alert) => alert.alertname).join(', ')}`.slice(0, 180);
  const text = [
    `Dirizhor critical alert status: ${payload.status}.`,
    ...payload.alerts.map((alert) => `alert=${alert.alertname} service=${alert.service} namespace=${alert.namespace}`),
    'See the private monitoring console for details.',
  ].join('\n');
  return { idempotencyKey, from: config.from, to: [config.to], subject, text };
}

async function sendWithRetry(email, config, doFetch) {
  let lastError;
  for (let attempt = 0; attempt <= config.retryDelays.length; attempt += 1) {
    try {
      const result = await sendOnce(email, config, doFetch);
      if (result.ok) return result;
      if (!result.retryable) throw new RelayError(502, `provider_${result.status}`);
      lastError = new RelayError(502, `provider_${result.status}`);
    } catch (error) {
      if (error instanceof RelayError && error.status === 502) lastError = error;
      else throw error;
    }
    const delay = config.retryDelays[attempt];
    if (delay !== undefined) await sleep(delay);
  }
  throw lastError ?? new RelayError(502, 'provider_unavailable');
}

async function sendOnce(email, config, doFetch) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), config.timeoutMs);
  try {
    const response = await doFetch(resendUrl, {
      method: 'POST',
      signal: controller.signal,
      headers: {
        authorization: `Bearer ${config.apiKey}`,
        'content-type': 'application/json',
        'idempotency-key': email.idempotencyKey,
        'user-agent': 'dirizhor-alert-relay/1.0',
      },
      body: JSON.stringify({ from: email.from, to: email.to, subject: email.subject, text: email.text }),
    });
    if (!response.ok) return { ok: false, status: response.status, retryable: response.status === 429 || response.status >= 500 };
    const body = await response.json().catch(() => ({}));
    return { ok: true, status: response.status, providerId: typeof body.id === 'string' ? body.id : 'unavailable' };
  } catch (error) {
    if (error?.name === 'AbortError') return { ok: false, status: 504, retryable: true };
    return { ok: false, status: 503, retryable: true };
  } finally {
    clearTimeout(timer);
  }
}

async function readJson(request) {
  let size = 0;
  const chunks = [];
  for await (const chunk of request) {
    size += chunk.length;
    if (size > maxBodyBytes) throw new RelayError(400, 'body_too_large');
    chunks.push(chunk);
  }
  try {
    return JSON.parse(Buffer.concat(chunks).toString('utf8'));
  } catch {
    throw new RelayError(400, 'invalid_json');
  }
}

function authorized(header, token) {
  if (typeof header !== 'string' || !header.startsWith('Bearer ')) return false;
  const received = Buffer.from(header.slice(7));
  const expected = Buffer.from(token);
  return received.length === expected.length && timingSafeEqual(received, expected);
}

function requiredEmail(value, name) {
  if (typeof value !== 'string' || !/^[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+$/.test(value)) throw new RelayError(500, name);
  return value;
}

function safeLabel(value, name) {
  if (typeof value !== 'string' || value.length === 0 || value.length > 128 || !/^[A-Za-z0-9_.:/-]+$/.test(value)) throw new RelayError(400, name);
  return value;
}

function positiveInteger(value, name, max) {
  if (!/^[1-9][0-9]*$/.test(value)) throw new RelayError(500, name);
  const integer = Number(value);
  if (!Number.isSafeInteger(integer) || integer > max) throw new RelayError(500, name);
  return integer;
}

function parseRetryDelays(value) {
  const delays = value.split(',').map((item) => positiveInteger(item, 'RETRY_DELAYS_MS', 5000));
  if (delays.length > 2) throw new RelayError(500, 'RETRY_DELAYS_MS');
  return delays;
}

async function readSecret(path, name) {
  if (typeof path !== 'string' || !path.startsWith('/')) throw new RelayError(500, name);
  const value = (await readFile(path, 'utf8')).trim();
  if (value.length < 16 || value.length > 512) throw new RelayError(500, name);
  return value;
}

function respond(response, status, value) {
  response.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store' });
  response.end(JSON.stringify(value));
}

function safeReason(error) {
  return error instanceof RelayError ? error.reason : 'unexpected';
}

function record(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function sleep(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

class RelayError extends Error {
  constructor(status, reason) {
    super(reason);
    this.status = status;
    this.reason = reason;
  }
}

if (process.argv[1] && new URL(import.meta.url).pathname === process.argv[1]) {
  const config = await createRelayConfig();
  const server = createRelayServer(config);
  server.listen(8080, '0.0.0.0');
}
