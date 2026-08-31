import { createServer, type Server } from 'node:http';

export interface HttpMetricRecorder {
  recordHttpResponse(route: string | undefined, statusCode: number, durationSeconds: number): void;
  recordReadiness(ready: boolean): void;
}

interface RequestCount {
  route: string;
  statusClass: string;
  count: number;
}

interface DurationSample {
  route: string;
  count: number;
  sum: number;
  buckets: number[];
}

const durationBuckets = [0.05, 0.1, 0.25, 0.5, 1, 2.5, 5] as const;

export class PrometheusMetrics implements HttpMetricRecorder {
  readonly #startedAtSeconds = Math.floor(Date.now() / 1_000);
  #ready = true;
  #queuePending = 0;
  #queueOldestSeconds = 0;
  #queueScanFailures = 0;
  readonly #requestCounts = new Map<string, RequestCount>();
  readonly #durations = new Map<string, DurationSample>();

  constructor(private readonly service: string) {}

  recordHttpResponse(route: string | undefined, statusCode: number, durationSeconds: number): void {
    const safeRoute = metricRoute(route);
    const statusClass = `${Math.floor(statusCode / 100)}xx`;
    const countKey = `${safeRoute}\u0000${statusClass}`;
    const count = this.#requestCounts.get(countKey) ?? {
      route: safeRoute,
      statusClass,
      count: 0,
    };
    count.count += 1;
    this.#requestCounts.set(countKey, count);

    const duration = this.#durations.get(safeRoute) ?? {
      route: safeRoute,
      count: 0,
      sum: 0,
      buckets: durationBuckets.map(() => 0),
    };
    duration.count += 1;
    duration.sum += Math.max(0, durationSeconds);
    for (const [index, bucket] of durationBuckets.entries()) {
      if (durationSeconds <= bucket) {
        duration.buckets[index] = (duration.buckets[index] ?? 0) + 1;
      }
    }
    this.#durations.set(safeRoute, duration);
  }

  recordReadiness(ready: boolean): void {
    this.#ready = ready;
  }

  recordQueue(pending: number, oldestSeconds: number): void {
    this.#queuePending = nonNegativeInteger(pending);
    this.#queueOldestSeconds = nonNegativeSeconds(oldestSeconds);
  }

  recordQueueScanFailure(): void {
    this.#queueScanFailures += 1;
  }

  render(): string {
    const lines = [
      '# HELP dirizhor_service_up Process is responding on its internal metrics port.',
      '# TYPE dirizhor_service_up gauge',
      `dirizhor_service_up{service="${this.service}"} 1`,
      '# HELP dirizhor_readiness Last dependency readiness result recorded by the service.',
      '# TYPE dirizhor_readiness gauge',
      `dirizhor_readiness{service="${this.service}"} ${this.#ready ? 1 : 0}`,
      '# HELP dirizhor_gateway_queue_pending Pending Gateway execution records.',
      '# TYPE dirizhor_gateway_queue_pending gauge',
      `dirizhor_gateway_queue_pending{service="${this.service}"} ${this.#queuePending}`,
      '# HELP dirizhor_gateway_queue_oldest_seconds Age of the oldest pending Gateway execution record.',
      '# TYPE dirizhor_gateway_queue_oldest_seconds gauge',
      `dirizhor_gateway_queue_oldest_seconds{service="${this.service}"} ${this.#queueOldestSeconds}`,
      '# HELP dirizhor_gateway_queue_scan_failures_total Failed pending-queue metric collection attempts.',
      '# TYPE dirizhor_gateway_queue_scan_failures_total counter',
      `dirizhor_gateway_queue_scan_failures_total{service="${this.service}"} ${this.#queueScanFailures}`,
      '# HELP process_start_time_seconds Unix time when the process started.',
      '# TYPE process_start_time_seconds gauge',
      `process_start_time_seconds{service="${this.service}"} ${this.#startedAtSeconds}`,
      '# HELP dirizhor_http_requests_total Completed HTTP requests by normalized route and status class.',
      '# TYPE dirizhor_http_requests_total counter',
    ];
    for (const count of this.#requestCounts.values()) {
      lines.push(
        `dirizhor_http_requests_total{service="${this.service}",route="${count.route}",status_class="${count.statusClass}"} ${count.count}`,
      );
    }
    lines.push(
      '# HELP dirizhor_http_request_duration_seconds Completed HTTP request duration by normalized route.',
      '# TYPE dirizhor_http_request_duration_seconds histogram',
    );
    for (const duration of this.#durations.values()) {
      for (const [index, bucket] of durationBuckets.entries()) {
        lines.push(
          `dirizhor_http_request_duration_seconds_bucket{service="${this.service}",route="${duration.route}",le="${bucket}"} ${duration.buckets[index]}`,
        );
      }
      lines.push(
        `dirizhor_http_request_duration_seconds_bucket{service="${this.service}",route="${duration.route}",le="+Inf"} ${duration.count}`,
        `dirizhor_http_request_duration_seconds_sum{service="${this.service}",route="${duration.route}"} ${duration.sum}`,
        `dirizhor_http_request_duration_seconds_count{service="${this.service}",route="${duration.route}"} ${duration.count}`,
      );
    }
    return `${lines.join('\n')}\n`;
  }
}

export async function startMetricsServer({
  host,
  port,
  metrics,
}: {
  host: '127.0.0.1' | '0.0.0.0';
  port: number;
  metrics: PrometheusMetrics;
}): Promise<Server> {
  const server = createServer((request, response) => {
    if (request.method !== 'GET' || request.url !== '/metrics') {
      response.writeHead(404, { 'cache-control': 'no-store' });
      response.end();
      return;
    }
    response.writeHead(200, {
      'cache-control': 'no-store',
      'content-type': 'text/plain; version=0.0.4; charset=utf-8',
      'x-content-type-options': 'nosniff',
    });
    response.end(metrics.render());
  });
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen({ host, port }, () => {
      server.off('error', reject);
      resolve();
    });
  });
  return server;
}

export async function closeMetricsServer(server: Server | undefined): Promise<void> {
  if (server === undefined) return;
  await new Promise<void>((resolve, reject) => {
    server.close((error) => (error === undefined ? resolve() : reject(error)));
  });
}

export function metricRoute(route: string | undefined): string {
  if (route === undefined || !/^\/[A-Za-z0-9_./:{}-]{1,160}$/.test(route)) {
    return 'unmatched';
  }
  return route;
}

function nonNegativeInteger(value: number): number {
  return Number.isSafeInteger(value) && value >= 0 ? value : 0;
}

function nonNegativeSeconds(value: number): number {
  return Number.isFinite(value) && value >= 0 ? value : 0;
}
