import { describe, expect, it } from 'vitest';

import { metricRoute, PrometheusMetrics } from '../src/metrics.js';

describe('Gateway Prometheus metrics', () => {
  it('exports bounded route labels and cumulative duration buckets', () => {
    const metrics = new PrometheusMetrics('gateway');
    metrics.recordReadiness(false);
    metrics.recordHttpResponse('/internal/v1/agent-runs/:agent_run_id::execute', 202, 0.08);
    metrics.recordHttpResponse(undefined, 500, 1.2);

    const rendered = metrics.render();
    expect(rendered).toContain('dirizhor_service_up{service="gateway"} 1');
    expect(rendered).toContain('dirizhor_readiness{service="gateway"} 0');
    expect(rendered).toContain('route="/internal/v1/agent-runs/:agent_run_id::execute",status_class="2xx"} 1');
    expect(rendered).toContain('route="unmatched",status_class="5xx"} 1');
    expect(rendered).toContain('route="unmatched",le="2.5"} 1');
    expect(metricRoute('/internal/run?capability=never')).toBe('unmatched');
  });
});
