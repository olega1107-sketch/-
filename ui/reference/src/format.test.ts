import { describe, expect, it } from 'vitest';

import type { Confirmation } from './api.js';
import { agentRunStatusLabel, expiryLabel, operationLabel, shortId } from './format.js';

const confirmation: Confirmation = {
  id: '10000000-0000-4000-8000-000000000001',
  operation: 'agent_context_share',
  target_type: 'agent_run',
  target_id: '10000000-0000-4000-8000-000000000002',
  project_id: '10000000-0000-4000-8000-000000000003',
  requested_by_user_id: '10000000-0000-4000-8000-000000000004',
  decided_by_user_id: null,
  authorization_decision_id: '10000000-0000-4000-8000-000000000005',
  request_id: '10000000-0000-4000-8000-000000000006',
  status: 'pending',
  payload_hash: `sha256:${'a'.repeat(64)}`,
  summary: 'Share context',
  created_at: '2030-01-01T09:00:00.000Z',
  expires_at: '2030-01-01T10:30:00.000Z',
  decided_at: null,
  consumed_at: null,
};

describe('confirmation formatters', () => {
  it('formats known operations and identifiers', () => {
    expect(operationLabel('agent_context_share')).toBe('Передача контекста агенту');
    expect(shortId(confirmation.id)).toBe('10000000');
  });

  it('shows remaining time without exposing payload details', () => {
    expect(expiryLabel(confirmation, Date.parse('2030-01-01T10:00:00.000Z'))).toBe(
      'Осталось 30 мин',
    );
    expect(expiryLabel(confirmation, Date.parse('2030-01-01T11:00:00.000Z'))).toBe('Срок истёк');
  });

  it('labels agent run states for the workbench', () => {
    expect(agentRunStatusLabel('awaiting_user_confirmation')).toBe('Ожидает подтверждения');
    expect(agentRunStatusLabel('completed')).toBe('Готово');
  });
});
