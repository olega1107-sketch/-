import type { Confirmation, ConfirmationStatus } from './api.js';

const operationLabels: Record<string, string> = {
  agent_context_share: 'Передача контекста агенту',
  bulk_context_share: 'Передача большого контекста',
  ai_result_save: 'Сохранение результата AI',
  decision_approve: 'Утверждение решения',
  decision_supersede: 'Замена решения',
  sensitivity_lower: 'Снижение чувствительности',
  break_glass_project_recovery: 'Аварийное восстановление проекта',
};

export const statusLabels: Record<ConfirmationStatus, string> = {
  pending: 'Ожидает',
  approved: 'Подтверждено',
  rejected: 'Отклонено',
  expired: 'Истекло',
  consumed: 'Выполнено',
  revoked: 'Отозвано',
};

export function operationLabel(operation: string): string {
  return operationLabels[operation] ?? operation;
}

export function agentRunStatusLabel(status: string): string {
  const labels: Record<string, string> = {
    awaiting_user_confirmation: 'Ожидает подтверждения',
    queued: 'В очереди',
    running: 'Выполняется',
    completed: 'Готово',
    failed: 'Не выполнено',
    cancelled: 'Отменено',
  };
  return labels[status] ?? status;
}

export function shortId(value: string): string {
  return value.slice(0, 8);
}

export function formatDate(value: string): string {
  return new Intl.DateTimeFormat('ru-RU', {
    day: '2-digit',
    month: 'short',
    hour: '2-digit',
    minute: '2-digit',
  }).format(new Date(value));
}

export function expiryLabel(confirmation: Confirmation, now = Date.now()): string {
  if (confirmation.status !== 'pending') return formatDate(confirmation.decided_at ?? confirmation.created_at);
  const deltaMinutes = Math.round((new Date(confirmation.expires_at).getTime() - now) / 60_000);
  if (deltaMinutes <= 0) return 'Срок истёк';
  if (deltaMinutes < 60) return `Осталось ${deltaMinutes} мин`;
  const hours = Math.round(deltaMinutes / 60);
  return `Осталось ${hours} ч`;
}
