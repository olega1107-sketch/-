import {
  ArrowRight,
  AudioLines,
  CheckCheck,
  ChevronDown,
  Clock3,
  FileCheck2,
  LogOut,
  RefreshCw,
  ShieldCheck,
  TriangleAlert,
  X,
  createIcons,
} from 'lucide';

import {
  ApiError,
  clearSession,
  decideConfirmation,
  localLoginEnabled,
  listConfirmations,
  listProjects,
  login,
  logout,
  oidcLoginUrl,
  type Confirmation,
  type ConfirmationStatus,
  type Project,
} from './api.js';
import { expiryLabel, formatDate, operationLabel, shortId, statusLabels } from './format.js';
import './style.css';

const icons = {
  ArrowRight,
  AudioLines,
  CheckCheck,
  ChevronDown,
  Clock3,
  FileCheck2,
  LogOut,
  RefreshCw,
  ShieldCheck,
  TriangleAlert,
  X,
};

let projects: Project[] = [];
let confirmations: Confirmation[] = [];
let currentStatus: ConfirmationStatus = 'pending';
let nextCursor: string | null = null;
let pendingCountLabel = '0';
let pendingDecision: { confirmation: Confirmation; action: 'approve' | 'reject' } | null = null;
let toastTimer: number | undefined;

const authView = required<HTMLElement>('auth-view');
const workspace = required<HTMLElement>('workspace');
const authForm = required<HTMLFormElement>('auth-form');
const authError = required<HTMLElement>('auth-error');
const localLogin = required<HTMLElement>('local-login');
const oidcLogin = required<HTMLAnchorElement>('oidc-login');
const projectSelect = required<HTMLSelectElement>('project-select');
const projectLabel = required<HTMLElement>('project-label');
const projectTrigger = required<HTMLButtonElement>('project-trigger');
const list = required<HTMLElement>('confirmation-list');
const listRegion = required<HTMLElement>('.list-region');
const emptyState = required<HTMLElement>('empty-state');
const errorState = required<HTMLElement>('error-state');
const errorMessage = required<HTMLElement>('error-message');
const listFooter = required<HTMLElement>('list-footer');
const moreButton = required<HTMLButtonElement>('more-button');
const refreshButton = required<HTMLButtonElement>('refresh-button');
const retryButton = required<HTMLButtonElement>('retry-button');
const logoutButton = required<HTMLButtonElement>('logout-button');
const lastUpdate = required<HTMLElement>('last-update');
const pendingSummary = required<HTMLElement>('pending-summary');
const navCount = required<HTMLElement>('nav-count');
const dialog = required<HTMLDialogElement>('decision-dialog');
const dialogTitle = required<HTMLElement>('dialog-title');
const dialogSummary = required<HTMLElement>('dialog-summary');
const dialogEyebrow = required<HTMLElement>('dialog-eyebrow');
const dialogConfirm = required<HTMLButtonElement>('dialog-confirm');
const dialogIcon = required<HTMLElement>('dialog-icon');
const toast = required<HTMLElement>('toast');

authForm.addEventListener('submit', (event) => void authenticate(event));
oidcLogin.href = oidcLoginUrl;
localLogin.hidden = !localLoginEnabled;
projectSelect.addEventListener('change', () => {
  updateProjectLabel();
  void loadQueue(true);
});
projectTrigger.addEventListener('click', () => {
  try {
    projectSelect.showPicker();
  } catch {
    projectSelect.click();
  }
});
refreshButton.addEventListener('click', () => void loadQueue(true));
retryButton.addEventListener('click', () => void loadWorkspace());
moreButton.addEventListener('click', () => void loadQueue(false));
logoutButton.addEventListener('click', () => void signOut());
dialog.addEventListener('close', () => void finishDecision());
document.querySelectorAll<HTMLButtonElement>('.tab').forEach((tab) => {
  tab.addEventListener('click', () => void selectStatus(tab));
});

createIcons({ icons });
void initialize();

async function initialize(): Promise<void> {
  const authFailure = new URL(window.location.href).searchParams.get('auth_error');
  if (authFailure !== null) {
    authError.textContent = oidcFailureMessage(authFailure);
    authError.hidden = false;
    window.history.replaceState({}, '', window.location.pathname);
    showAuth();
    return;
  }
  await loadWorkspace();
}

async function authenticate(event: SubmitEvent): Promise<void> {
  event.preventDefault();
  const submit = authForm.querySelector<HTMLButtonElement>('button[type="submit"]');
  const data = new FormData(authForm);
  setBusy(submit, true);
  authError.hidden = true;
  try {
    await login(String(data.get('login') ?? ''), String(data.get('password') ?? ''));
    authForm.reset();
    await loadWorkspace();
  } catch (error) {
    authError.textContent = messageFor(error);
    authError.hidden = false;
  } finally {
    setBusy(submit, false);
  }
}

async function loadWorkspace(): Promise<void> {
  showWorkspace();
  setRegionLoading(true);
  try {
    projects = await collectProjects();
    renderProjects();
    await loadQueue(true);
  } catch (error) {
    handleRequestError(error);
  } finally {
    setRegionLoading(false);
  }
}

async function collectProjects(): Promise<Project[]> {
  const result: Project[] = [];
  let cursor: string | undefined;
  do {
    const page = await listProjects(cursor);
    result.push(...page.items);
    cursor = page.next_cursor ?? undefined;
  } while (cursor !== undefined);
  return result;
}

function renderProjects(): void {
  projectSelect.replaceChildren();
  for (const project of projects) {
    const option = document.createElement('option');
    option.value = project.id;
    option.textContent = project.status === 'archived' ? `${project.title} · архив` : project.title;
    projectSelect.append(option);
  }
  projectSelect.disabled = projects.length === 0;
  projectTrigger.disabled = projects.length === 0;
  updateProjectLabel();
}

function updateProjectLabel(): void {
  projectLabel.textContent = projectSelect.selectedOptions[0]?.textContent ?? 'Нет доступных проектов';
}

async function loadQueue(reset: boolean): Promise<void> {
  const projectId = projectSelect.value;
  if (projectId.length === 0) {
    confirmations = [];
    nextCursor = null;
    renderQueue();
    return;
  }
  setRegionLoading(true);
  errorState.hidden = true;
  try {
    const page = await listConfirmations(
      projectId,
      currentStatus,
      reset ? undefined : nextCursor ?? undefined,
    );
    confirmations = reset ? page.items : [...confirmations, ...page.items];
    nextCursor = page.next_cursor;
    renderQueue();
    lastUpdate.textContent = new Intl.DateTimeFormat('ru-RU', {
      hour: '2-digit', minute: '2-digit',
    }).format(new Date());
  } catch (error) {
    handleRequestError(error);
  } finally {
    setRegionLoading(false);
  }
}

function renderQueue(): void {
  list.replaceChildren(...confirmations.map(confirmationCard));
  const isEmpty = confirmations.length === 0;
  emptyState.hidden = !isEmpty;
  emptyState.querySelector('p')!.textContent = currentStatus === 'pending'
    ? 'Новых операций для решения нет.'
    : 'В этом разделе пока нет операций.';
  listFooter.hidden = nextCursor === null;
  if (currentStatus === 'pending') {
    pendingCountLabel = `${confirmations.length}${nextCursor === null ? '' : '+'}`;
  }
  pendingSummary.querySelector('.summary-value')!.textContent = pendingCountLabel;
  navCount.textContent = pendingCountLabel;
  navCount.hidden = pendingCountLabel === '0';
  createIcons({ icons });
}

function confirmationCard(confirmation: Confirmation): HTMLElement {
  const article = document.createElement('article');
  article.className = `confirmation-card status-${confirmation.status}`;
  const actions = confirmation.status === 'pending'
    ? `<div class="card-actions">
         <button class="button danger-quiet reject" type="button"><i data-lucide="x"></i><span>Отклонить</span></button>
         <button class="button primary approve" type="button"><i data-lucide="shield-check"></i><span>Подтвердить</span></button>
       </div>`
    : '';
  article.innerHTML = `
    <div class="card-icon"><i data-lucide="${confirmation.operation === 'ai_result_save' ? 'file-check-2' : 'shield-check'}"></i></div>
    <div class="card-body">
      <div class="card-topline">
        <span class="operation-label">${escapeHtml(operationLabel(confirmation.operation))}</span>
        <span class="status-badge ${confirmation.status}">${statusLabels[confirmation.status]}</span>
      </div>
      <h2>${escapeHtml(confirmation.summary)}</h2>
      <div class="card-meta">
        <span><i data-lucide="clock-3"></i>${escapeHtml(expiryLabel(confirmation))}</span>
        <span>Создано ${escapeHtml(formatDate(confirmation.created_at))}</span>
        <span>Запрос ${shortId(confirmation.request_id)}</span>
      </div>
      <details>
        <summary>Технические данные</summary>
        <dl>
          <div><dt>Операция</dt><dd>${escapeHtml(confirmation.operation)}</dd></div>
          <div><dt>Цель</dt><dd>${escapeHtml(confirmation.target_type)} · ${shortId(confirmation.target_id)}</dd></div>
          <div><dt>Инициатор</dt><dd>${shortId(confirmation.requested_by_user_id)}</dd></div>
          <div><dt>Контрольная сумма</dt><dd>${escapeHtml(confirmation.payload_hash.slice(0, 22))}…</dd></div>
        </dl>
      </details>
    </div>
    ${actions}`;
  article.querySelector('.approve')?.addEventListener('click', () => openDecision(confirmation, 'approve'));
  article.querySelector('.reject')?.addEventListener('click', () => openDecision(confirmation, 'reject'));
  return article;
}

function openDecision(confirmation: Confirmation, action: 'approve' | 'reject'): void {
  pendingDecision = { confirmation, action };
  const approve = action === 'approve';
  dialogEyebrow.textContent = approve ? 'Подтверждение операции' : 'Отклонение операции';
  dialogTitle.textContent = approve ? 'Разрешить выполнение?' : 'Отклонить запрос?';
  dialogSummary.textContent = confirmation.summary;
  dialogConfirm.textContent = approve ? 'Подтвердить' : 'Отклонить';
  dialogConfirm.className = approve ? 'button primary' : 'button danger';
  dialogIcon.className = approve ? 'dialog-icon' : 'dialog-icon reject';
  dialog.showModal();
}

async function finishDecision(): Promise<void> {
  if (dialog.returnValue !== 'confirm' || pendingDecision === null) {
    pendingDecision = null;
    return;
  }
  const { confirmation, action } = pendingDecision;
  pendingDecision = null;
  setRegionLoading(true);
  try {
    await decideConfirmation(confirmation.id, action);
    showToast(action === 'approve' ? 'Операция подтверждена' : 'Операция отклонена');
    await loadQueue(true);
  } catch (error) {
    handleRequestError(error);
  } finally {
    setRegionLoading(false);
  }
}

function selectStatus(tab: HTMLButtonElement): void {
  const status = tab.dataset.status as ConfirmationStatus | undefined;
  if (status === undefined || status === currentStatus) return;
  currentStatus = status;
  document.querySelectorAll<HTMLButtonElement>('.tab').forEach((item) => {
    const selected = item === tab;
    item.classList.toggle('active', selected);
    item.setAttribute('aria-selected', String(selected));
  });
  void loadQueue(true);
}

async function signOut(): Promise<void> {
  try {
    await logout();
  } catch {
    clearSession();
  }
  showAuth();
}

function handleRequestError(error: unknown): void {
  if (error instanceof ApiError && error.status === 401) {
    clearSession();
    showAuth();
    return;
  }
  errorMessage.textContent = messageFor(error);
  errorState.hidden = false;
  emptyState.hidden = true;
}

function showAuth(): void {
  workspace.hidden = true;
  authView.hidden = false;
  if (localLoginEnabled) {
    authForm.querySelector<HTMLInputElement>('input')?.focus();
  } else {
    oidcLogin.focus();
  }
}

function showWorkspace(): void {
  authView.hidden = true;
  workspace.hidden = false;
}

function setRegionLoading(loading: boolean): void {
  listRegion.setAttribute('aria-busy', String(loading));
  refreshButton.disabled = loading;
  refreshButton.classList.toggle('spinning', loading);
  moreButton.disabled = loading;
}

function setBusy(button: HTMLButtonElement | null, busy: boolean): void {
  if (button !== null) button.disabled = busy;
}

function showToast(message: string): void {
  if (toastTimer !== undefined) window.clearTimeout(toastTimer);
  toast.textContent = message;
  toast.hidden = false;
  toastTimer = window.setTimeout(() => { toast.hidden = true; }, 3200);
}

function messageFor(error: unknown): string {
  return error instanceof Error ? error.message : 'Неизвестная ошибка.';
}

function oidcFailureMessage(code: string): string {
  if (code === 'identity_not_provisioned') {
    return 'Учётная запись не подключена к «Дирижёру». Обратитесь к администратору.';
  }
  if (code === 'oidc_provider_unavailable') {
    return 'Корпоративный вход временно недоступен. Повторите попытку позже.';
  }
  return 'Корпоративный вход не завершён. Начните вход заново.';
}

function required<T extends Element>(selector: string): T {
  const element = selector.startsWith('.')
    ? document.querySelector<T>(selector)
    : document.getElementById(selector) as T | null;
  if (element === null) throw new Error(`Missing UI element: ${selector}`);
  return element;
}

function escapeHtml(value: string): string {
  const span = document.createElement('span');
  span.textContent = value;
  return span.innerHTML;
}
