import { describe, expect, it } from 'vitest';

import { metricRoute, PrometheusMetrics } from '../src/metrics.js';

describe('Director Prometheus metrics', () => {
  it('exports bounded route labels and cumulative duration buckets', () => {
    const metrics = new PrometheusMetrics('director');
    metrics.recordReadiness(false);
    metrics.recordHttpResponse('/api/v1/auth/oidc/callback', 302, 0.12);
    metrics.recordHttpResponse('/memory/tenant-secret', 500, 1.2);

    const rendered = metrics.render();
    expect(rendered).toContain('dirizhor_service_up{service="director"} 1');
    expect(rendered).toContain('dirizhor_readiness{service="director"} 0');
    expect(rendered).toContain('route="/api/v1/auth/oidc/callback",status_class="3xx"} 1');
    expect(rendered).toContain('route="/memory/tenant-secret",status_class="5xx"} 1');
    expect(rendered).toContain('route="/api/v1/auth/oidc/callback",le="0.25"} 1');
    expect(metricRoute('/user/123?token=never')).toBe('unmatched');
    expect(metricRoute(undefined)).toBe('unmatched');
  });
});
