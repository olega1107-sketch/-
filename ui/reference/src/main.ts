import {
  ArrowRight,
  AudioLines,
  Bot,
  CheckCheck,
  ChevronDown,
  Clock3,
  Database,
  FileCheck2,
  FileText,
  GitBranch,
  LogOut,
  Plus,
  RefreshCw,
  Search,
  ShieldCheck,
  Trash2,
  TriangleAlert,
  X,
  createIcons,
} from 'lucide';

import {
  ApiError,
  clearSession,
  createDecision,
  decideConfirmation,
  getDecisionProvenance,
  localLoginEnabled,
  listConfirmations,
  listProjects,
  login,
  createTask,
  createAgentRun,
  getAgentRun,
  getAgentRunResult,
  getMemoryObject,
  logout,
  oidcLoginUrl,
  requestDecisionApproval,
  supersedeDecision,
  searchTaskContext,
  uploadMemoryObject,
  type Confirmation,
  type ConfirmationStatus,
  type DecisionCreateInput,
  type DecisionProvenance,
  type DecisionSupersedeInput,
  type Project,
  type RelationshipEndpointType,
  type RelationshipType,
  type TaskContextCandidate,
} from './api.js';
import { agentRunStatusLabel, expiryLabel, formatDate, operationLabel, shortId, statusLabels } from './format.js';
import './style.css';

const icons = {
  ArrowRight,
  AudioLines,
  Bot,
  CheckCheck,
  ChevronDown,
  Clock3,
  Database,
  FileCheck2,
  FileText,
  GitBranch,
  LogOut,
  Plus,
  RefreshCw,
  Search,
  ShieldCheck,
  Trash2,
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
let currentView: 'confirmations' | 'decisions' | 'workbench' = 'confirmations';
let currentTask: { id: string; title: string; request: string } | null = null;
let contextCandidates: TaskContextCandidate[] = [];
let currentDecisionId: string | null = null;
let sourceRowSequence = 0;
let decisionFormMode: 'create' | 'supersede' = 'create';
let decisionFormTargetId: string | null = null;
let agentRunRefreshTimer: number | undefined;

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
const confirmationsView = required<HTMLElement>('confirmations-view');
const decisionsView = required<HTMLElement>('decisions-view');
const confirmationsNav = required<HTMLButtonElement>('confirmations-nav');
const decisionsNav = required<HTMLButtonElement>('decisions-nav');
const workbenchNav = required<HTMLButtonElement>('workbench-nav');
const workbenchView = required<HTMLElement>('workbench-view');
const uploadForm = required<HTMLFormElement>('upload-form');
const taskForm = required<HTMLFormElement>('task-form');
const contextPanel = required<HTMLElement>('context-panel');
const contextCandidatesRegion = required<HTMLElement>('context-candidates');
const taskSummary = required<HTMLElement>('task-summary');
const agentInstructions = required<HTMLTextAreaElement>('agent-instructions');
const agentType = required<HTMLSelectElement>('agent-type');
const runAgentButton = required<HTMLButtonElement>('run-agent-button');
const workbenchError = required<HTMLElement>('workbench-error');
const agentResult = required<HTMLElement>('agent-result');
const agentRunStatus = required<HTMLElement>('agent-run-status');
const agentRunError = required<HTMLElement>('agent-run-error');
const agentRunContent = required<HTMLPreElement>('agent-run-content');
const decisionLookupForm = required<HTMLFormElement>('decision-lookup-form');
const decisionIdInput = required<HTMLInputElement>('decision-id-input');
const decisionRegion = required<HTMLElement>('decision-region');
const decisionEmpty = required<HTMLElement>('decision-empty');
const decisionError = required<HTMLElement>('decision-error');
const decisionErrorMessage = required<HTMLElement>('decision-error-message');
const decisionDetail = required<HTMLElement>('decision-detail');
const newDecisionButton = required<HTMLButtonElement>('new-decision-button');
const createDecisionDialog = required<HTMLDialogElement>('create-decision-dialog');
const createDecisionForm = required<HTMLFormElement>('create-decision-form');
const createDecisionError = required<HTMLElement>('create-decision-error');
const createDialogClose = required<HTMLButtonElement>('create-dialog-close');
const createDialogCancel = required<HTMLButtonElement>('create-dialog-cancel');
const addSourceButton = required<HTMLButtonElement>('add-source-button');
const sourceList = required<HTMLElement>('source-list');
const decisionFormEyebrow = required<HTMLElement>('decision-form-eyebrow');
const decisionFormTitle = required<HTMLElement>('decision-form-title');
const decisionStatusField = required<HTMLElement>('decision-status-field');
const decisionFormSubmit = required<HTMLButtonElement>('decision-form-submit');
const decisionFormSubmitLabel = required<HTMLElement>('decision-form-submit-label');

authForm.addEventListener('submit', (event) => void authenticate(event));
oidcLogin.href = oidcLoginUrl;
localLogin.hidden = !localLoginEnabled;
projectSelect.addEventListener('change', () => {
  updateProjectLabel();
  currentDecisionId = null;
  renderNoDecision();
  void refreshCurrentView();
});
projectTrigger.addEventListener('click', () => {
  try {
    projectSelect.showPicker();
  } catch {
    projectSelect.click();
  }
});
refreshButton.addEventListener('click', () => void refreshCurrentView());
retryButton.addEventListener('click', () => void loadWorkspace());
moreButton.addEventListener('click', () => void loadQueue(false));
logoutButton.addEventListener('click', () => void signOut());
dialog.addEventListener('close', () => void finishDecision());
confirmationsNav.addEventListener('click', () => selectWorkspaceView('confirmations'));
decisionsNav.addEventListener('click', () => selectWorkspaceView('decisions'));
workbenchNav.addEventListener('click', () => selectWorkspaceView('workbench'));
uploadForm.addEventListener('submit', (event) => void submitUpload(event));
taskForm.addEventListener('submit', (event) => void submitTask(event));
runAgentButton.addEventListener('click', () => void submitAgentRun());
decisionLookupForm.addEventListener('submit', (event) => void lookupDecision(event));
newDecisionButton.addEventListener('click', () => openCreateDecisionDialog());
createDialogClose.addEventListener('click', () => createDecisionDialog.close());
createDialogCancel.addEventListener('click', () => createDecisionDialog.close());
addSourceButton.addEventListener('click', () => addSourceRow());
createDecisionForm.addEventListener('submit', (event) => void submitDecision(event));
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
    await refreshCurrentView();
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

function selectWorkspaceView(
  view: 'confirmations' | 'decisions' | 'workbench',
  refresh = true,
): void {
  currentView = view;
  confirmationsView.hidden = view !== 'confirmations';
  decisionsView.hidden = view !== 'decisions';
  workbenchView.hidden = view !== 'workbench';
  confirmationsNav.classList.toggle('active', view === 'confirmations');
  decisionsNav.classList.toggle('active', view === 'decisions');
  workbenchNav.classList.toggle('active', view === 'workbench');
  if (view === 'confirmations' && refresh) {
    void loadQueue(true);
  }
}

async function submitUpload(event: SubmitEvent): Promise<void> {
  event.preventDefault();
  if (!uploadForm.reportValidity() || projectSelect.value.length === 0) return;
  const data = new FormData(uploadForm);
  const file = data.get('file');
  if (!(file instanceof File) || file.size === 0) return;
  const submit = uploadForm.querySelector<HTMLButtonElement>('button[type="submit"]');
  setBusy(submit, true);
  try {
    await uploadMemoryObject({ project_id: projectSelect.value, title: String(data.get('title') ?? ''), type: 'document', sensitivity_level: String(data.get('sensitivity_level')) as DecisionCreateInput['sensitivity_level'], file });
    uploadForm.reset(); showToast('Документ добавлен в память');
  } catch (error) { showWorkbenchError(error); } finally { setBusy(submit, false); }
}

async function submitTask(event: SubmitEvent): Promise<void> {
  event.preventDefault();
  if (!taskForm.reportValidity() || projectSelect.value.length === 0) return;
  const data = new FormData(taskForm); const submit = taskForm.querySelector<HTMLButtonElement>('button[type="submit"]');
  setBusy(submit, true); workbenchError.hidden = true;
  try {
    const title = String(data.get('title') ?? '').trim(); const request = String(data.get('user_request') ?? '').trim();
    const task = await createTask({ project_id: projectSelect.value, title, user_request: request });
    const matches = await searchTaskContext(task.id, request);
    currentTask = { id: task.id, title, request }; contextCandidates = matches.candidates;
    renderContextCandidates(); contextPanel.hidden = false; taskSummary.textContent = title;
    contextPanel.scrollIntoView({ behavior: 'smooth', block: 'start' });
  } catch (error) { showWorkbenchError(error); } finally { setBusy(submit, false); }
}

function renderContextCandidates(): void {
  contextCandidatesRegion.replaceChildren(...contextCandidates.map((candidate) => {
    const label = document.createElement('label'); label.className = 'context-candidate';
    label.innerHTML = `<input type="checkbox" value="${escapeHtml(candidate.memory_object_id)}" /><span><strong>${escapeHtml(candidate.title)}</strong><small>${escapeHtml(candidate.reason)}</small></span>`;
    return label;
  }));
}

async function submitAgentRun(): Promise<void> {
  if (currentTask === null) return;
  const selected = [...contextCandidatesRegion.querySelectorAll<HTMLInputElement>('input:checked')];
  if (selected.length === 0 || agentInstructions.value.trim().length === 0) { showWorkbenchError(new Error('Выберите хотя бы один документ и добавьте инструкцию.')); return; }
  setBusy(runAgentButton, true); workbenchError.hidden = true;
  try {
    const context = await Promise.all(selected.map(async (item) => {
      const memory = await getMemoryObject(item.value);
      if (memory.current_version === null) throw new Error(`Для «${memory.title}» нет доступной версии.`);
      return { memory_object_id: memory.id, document_version_id: memory.current_version.id, access_reason: currentTask!.request };
    }));
    const run = await createAgentRun(currentTask.id, { agent_type: agentType.value, purpose: currentTask.title, instructions: agentInstructions.value.trim(), context });
    renderAgentRun(run);
    showToast(run.status === 'awaiting_user_confirmation' ? 'Запуск ожидает подтверждения' : 'Анализ запущен');
    if (run.status === 'awaiting_user_confirmation') selectWorkspaceView('confirmations');
  } catch (error) { showWorkbenchError(error); } finally { setBusy(runAgentButton, false); }
}

function showWorkbenchError(error: unknown): void { workbenchError.textContent = messageFor(error); workbenchError.hidden = false; }

function renderAgentRun(run: { id: string; status: string; error_message: string | null }): void {
  if (agentRunRefreshTimer !== undefined) window.clearTimeout(agentRunRefreshTimer);
  agentResult.hidden = false;
  agentRunStatus.textContent = agentRunStatusLabel(run.status);
  agentRunError.hidden = true;
  agentRunContent.hidden = true;
  if (run.status === 'failed') {
    agentRunError.textContent = run.error_message ?? 'Анализ не был завершён.';
    agentRunError.hidden = false;
    return;
  }
  if (run.status === 'completed') {
    void loadAgentResult(run.id);
    return;
  }
  if (run.status === 'queued' || run.status === 'running') {
    agentRunRefreshTimer = window.setTimeout(() => void refreshAgentRun(run.id), 1_500);
  }
}

async function refreshAgentRun(agentRunId: string): Promise<void> {
  try {
    renderAgentRun(await getAgentRun(agentRunId));
  } catch (error) {
    agentResult.hidden = false;
    agentRunError.textContent = messageFor(error);
    agentRunError.hidden = false;
  }
}

async function loadAgentResult(agentRunId: string): Promise<void> {
  try {
    const result = await getAgentRunResult(agentRunId);
    agentRunContent.textContent = result.content;
    agentRunContent.hidden = false;
  } catch (error) {
    agentRunError.textContent = messageFor(error);
    agentRunError.hidden = false;
  }
}

async function refreshCurrentView(): Promise<void> {
  if (currentView === 'confirmations') {
    await loadQueue(true);
    return;
  }
  if (currentDecisionId !== null) {
    await loadDecision(currentDecisionId);
  }
}

async function lookupDecision(event: SubmitEvent): Promise<void> {
  event.preventDefault();
  if (!decisionLookupForm.reportValidity()) return;
  await loadDecision(decisionIdInput.value.trim());
}

async function loadDecision(decisionId: string): Promise<void> {
  setDecisionLoading(true);
  decisionError.hidden = true;
  decisionEmpty.hidden = true;
  try {
    const provenance = await getDecisionProvenance(decisionId);
    currentDecisionId = provenance.decision.id;
    decisionIdInput.value = provenance.decision.id;
    if (projects.some((project) => project.id === provenance.decision.project_id)) {
      projectSelect.value = provenance.decision.project_id;
      updateProjectLabel();
    }
    renderDecision(provenance);
    lastUpdate.textContent = new Intl.DateTimeFormat('ru-RU', {
      hour: '2-digit', minute: '2-digit',
    }).format(new Date());
  } catch (error) {
    if (error instanceof ApiError && error.status === 401) {
      clearSession();
      showAuth();
      return;
    }
    decisionDetail.hidden = true;
    decisionErrorMessage.textContent = messageFor(error);
    decisionError.hidden = false;
  } finally {
    setDecisionLoading(false);
  }
}

function renderDecision(provenance: DecisionProvenance): void {
  const decision = provenance.decision;
  const actions = decision.status === 'draft' || decision.status === 'proposed'
    ? `<div class="decision-actions"><button class="button primary" data-decision-action="approve" type="button"><i data-lucide="shield-check"></i><span>Запросить утверждение</span></button></div>`
    : decision.status === 'approved'
      ? `<div class="decision-actions"><button class="button secondary" data-decision-action="supersede" type="button"><i data-lucide="git-branch"></i><span>Заменить решение</span></button></div>`
      : '';
  const rationale = decision.rationale === null
    ? ''
    : `<div class="decision-rationale"><h3>Обоснование</h3><p>${escapeHtml(decision.rationale)}</p></div>`;
  decisionDetail.innerHTML = `
    <header class="decision-summary">
      <div class="decision-summary-copy">
        <div class="card-topline">
          <span class="status-badge decision-${escapeHtml(decision.status)}">${escapeHtml(decisionStatusLabel(decision.status))}</span>
          <span class="sensitivity-label">${escapeHtml(sensitivityLabel(decision.sensitivity_level))}</span>
        </div>
        <h2>${escapeHtml(decision.title)}</h2>
        <p>${escapeHtml(decision.decision_text)}</p>
        ${rationale}
        ${actions}
      </div>
      <dl class="decision-identifiers">
        <div><dt>Решение</dt><dd>${escapeHtml(decision.id)}</dd></div>
        <div><dt>Карточка памяти</dt><dd>${escapeHtml(decision.memory_object_id)}</dd></div>
        <div><dt>Создано</dt><dd>${escapeHtml(formatDate(decision.created_at))}</dd></div>
      </dl>
    </header>
    <div class="provenance-grid">
      ${provenanceSection(
        'Связи',
        'git-branch',
        provenance.relationships.map((relationship) => `
          <article class="provenance-item">
            <strong>${escapeHtml(relationLabel(relationship.relation_type))}</strong>
            <span>${escapeHtml(endpointLabel(relationship.target_type))} · ${escapeHtml(shortId(relationship.target_id))}</span>
            ${relationship.description === null ? '' : `<p>${escapeHtml(relationship.description)}</p>`}
          </article>`),
      )}
      ${provenanceSection(
        'Объекты памяти',
        'database',
        provenance.related_memory_objects.map((memory) => `
          <article class="provenance-item">
            <strong>${escapeHtml(memory.title)}</strong>
            <span>${escapeHtml(memoryTypeLabel(memory.type))} · ${escapeHtml(shortId(memory.id))}</span>
          </article>`),
      )}
      ${provenanceSection(
        'Запуски агентов',
        'bot',
        provenance.agent_runs.map((run) => `
          <article class="provenance-item">
            <strong>${escapeHtml(run.agent_type)} · ${escapeHtml(run.provider)}</strong>
            <span>${escapeHtml(run.status)} · ${escapeHtml(shortId(run.id))}</span>
            <p>${escapeHtml(run.deployment_class === 'external' ? 'Внешний контур' : 'Внутренний контур')}</p>
          </article>`),
      )}
      ${provenanceSection(
        'Точные версии источников',
        'file-text',
        provenance.source_versions.map((source) => `
          <article class="provenance-item source-version">
            <strong>${escapeHtml(source.memory_object_title)} · v${source.version_number}</strong>
            <span>${escapeHtml(source.file_name)} · ${source.size_bytes.toLocaleString('ru-RU')} байт</span>
            <code>${escapeHtml(source.content_hash)}</code>
            <p>${escapeHtml(source.access_reason)}</p>
          </article>`),
      )}
      ${provenanceSection(
        'Аудит',
        'file-check-2',
        provenance.audit_events.map((audit) => `
          <article class="provenance-item">
            <strong>${escapeHtml(audit.action)}</strong>
            <span>${escapeHtml(formatDate(audit.created_at))} · ${escapeHtml(shortId(audit.request_id))}</span>
          </article>`),
      )}
    </div>`;
  decisionDetail.hidden = false;
  decisionEmpty.hidden = true;
  decisionError.hidden = true;
  decisionDetail.querySelector('[data-decision-action="approve"]')?.addEventListener(
    'click',
    () => void prepareDecisionApproval(decision.id),
  );
  decisionDetail.querySelector('[data-decision-action="supersede"]')?.addEventListener(
    'click',
    () => openSupersedeDecisionDialog(decision.id, decision.sensitivity_level),
  );
  createIcons({ icons });
}

function provenanceSection(title: string, icon: string, items: string[]): string {
  return `
    <section class="provenance-section">
      <header><i data-lucide="${icon}"></i><h3>${escapeHtml(title)}</h3><span>${items.length}</span></header>
      <div class="provenance-list">
        ${items.length === 0 ? '<p class="provenance-empty">Нет данных</p>' : items.join('')}
      </div>
    </section>`;
}

function renderNoDecision(): void {
  currentDecisionId = null;
  decisionIdInput.value = '';
  decisionDetail.hidden = true;
  decisionError.hidden = true;
  decisionEmpty.hidden = false;
}

function openCreateDecisionDialog(): void {
  if (projectSelect.value.length === 0) {
    showToast('Нет доступного проекта');
    return;
  }
  createDecisionForm.reset();
  decisionFormMode = 'create';
  decisionFormTargetId = null;
  decisionFormEyebrow.textContent = 'Human decision';
  decisionFormTitle.textContent = 'Новое решение';
  decisionFormSubmitLabel.textContent = 'Создать решение';
  decisionStatusField.hidden = false;
  createDecisionError.hidden = true;
  sourceList.replaceChildren();
  sourceRowSequence = 0;
  addSourceRow();
  createDecisionDialog.showModal();
  createDecisionForm.querySelector<HTMLInputElement>('input[name="title"]')?.focus();
}

function openSupersedeDecisionDialog(decisionId: string, sensitivity: string): void {
  decisionFormMode = 'supersede';
  decisionFormTargetId = decisionId;
  createDecisionForm.reset();
  createDecisionError.hidden = true;
  decisionFormEyebrow.textContent = 'Supersede';
  decisionFormTitle.textContent = 'Заменить решение';
  decisionFormSubmitLabel.textContent = 'Запросить замену';
  decisionStatusField.hidden = true;
  const sensitivitySelect = createDecisionForm.elements.namedItem('sensitivity_level');
  if (sensitivitySelect instanceof HTMLSelectElement) sensitivitySelect.value = sensitivity;
  sourceList.replaceChildren();
  sourceRowSequence = 0;
  addSourceRow();
  createDecisionDialog.showModal();
  createDecisionForm.querySelector<HTMLInputElement>('input[name="title"]')?.focus();
}

async function prepareDecisionApproval(decisionId: string): Promise<void> {
  setDecisionLoading(true);
  try {
    await requestDecisionApproval(decisionId);
    await loadDecision(decisionId);
    showToast('Решение уже утверждено');
  } catch (error) {
    if (error instanceof ApiError && error.status === 428) {
      selectWorkspaceView('confirmations', false);
      await loadQueue(true);
      showToast('Запрос утверждения создан');
      return;
    }
    decisionErrorMessage.textContent = messageFor(error);
    decisionError.hidden = false;
  } finally {
    setDecisionLoading(false);
  }
}

function addSourceRow(): void {
  if (sourceList.childElementCount >= 10) return;
  const row = document.createElement('div');
  row.className = 'source-row';
  row.dataset.sourceRow = String(sourceRowSequence++);
  row.innerHTML = `
    <label class="field"><span>Тип</span><select data-field="target_type">
      <option value="memory_object">Объект памяти</option>
      <option value="agent_run">Запуск агента</option>
      <option value="task">Задача</option>
      <option value="decision">Решение</option>
      <option value="open_question">Открытый вопрос</option>
    </select></label>
    <label class="field source-id"><span>ID источника</span><input data-field="target_id" type="text" required pattern="[0-9a-fA-F-]{36}" maxlength="36" /></label>
    <label class="field"><span>Связь</span><select data-field="relation_type">
      <option value="references">Ссылается</option>
      <option value="derived_from">Основано на</option>
      <option value="depends_on">Зависит от</option>
      <option value="explains">Объясняет</option>
      <option value="implements">Реализует</option>
      <option value="contradicts">Противоречит</option>
    </select></label>
    <button class="icon-button remove-source" type="button" aria-label="Удалить источник" title="Удалить источник"><i data-lucide="trash-2"></i></button>`;
  row.querySelector<HTMLButtonElement>('.remove-source')?.addEventListener('click', () => row.remove());
  sourceList.append(row);
  createIcons({ icons });
}

async function submitDecision(event: SubmitEvent): Promise<void> {
  event.preventDefault();
  if (!createDecisionForm.reportValidity()) return;
  const submit = decisionFormSubmit;
  const data = new FormData(createDecisionForm);
  const input: DecisionCreateInput = {
    project_id: projectSelect.value,
    title: String(data.get('title') ?? ''),
    decision_text: String(data.get('decision_text') ?? ''),
    rationale: nullableFormValue(data.get('rationale')),
    status: data.get('status') === 'proposed' ? 'proposed' : 'draft',
    sensitivity_level: String(data.get('sensitivity_level') ?? 'internal') as DecisionCreateInput['sensitivity_level'],
    relationships: collectRelationshipInputs(),
  };
  setBusy(submit, true);
  createDecisionError.hidden = true;
  try {
    if (decisionFormMode === 'supersede') {
      if (decisionFormTargetId === null) throw new Error('Decision target is missing.');
      const supersedeInput: DecisionSupersedeInput = {
        title: input.title,
        decision_text: input.decision_text,
        rationale: input.rationale ?? null,
        sensitivity_level: input.sensitivity_level,
        relationships: input.relationships,
      };
      const targetId = decisionFormTargetId;
      try {
        const result = await supersedeDecision(targetId, supersedeInput);
        createDecisionDialog.close();
        await loadDecision(result.new_decision.id);
        showToast('Решение заменено');
      } catch (error) {
        if (error instanceof ApiError && error.status === 428) {
          createDecisionDialog.close();
          selectWorkspaceView('confirmations', false);
          await loadQueue(true);
          showToast('Запрос замены создан');
          return;
        }
        throw error;
      }
      return;
    }
    const created = await createDecision(input);
    createDecisionDialog.close();
    selectWorkspaceView('decisions');
    await loadDecision(created.id);
    showToast('Решение создано');
  } catch (error) {
    createDecisionError.textContent = messageFor(error);
    createDecisionError.hidden = false;
  } finally {
    setBusy(submit, false);
  }
}

function collectRelationshipInputs(): DecisionCreateInput['relationships'] {
  return [...sourceList.querySelectorAll<HTMLElement>('.source-row')].map((row) => ({
    target_type: requiredField<HTMLSelectElement>(row, 'target_type').value as RelationshipEndpointType,
    target_id: requiredField<HTMLInputElement>(row, 'target_id').value.trim(),
    relation_type: requiredField<HTMLSelectElement>(row, 'relation_type').value as RelationshipType,
  }));
}

function requiredField<T extends HTMLInputElement | HTMLSelectElement>(row: HTMLElement, name: string): T {
  const field = row.querySelector<T>(`[data-field="${name}"]`);
  if (field === null) throw new Error(`Missing source field: ${name}`);
  return field;
}

function nullableFormValue(value: FormDataEntryValue | null): string | null {
  const text = typeof value === 'string' ? value.trim() : '';
  return text.length === 0 ? null : text;
}

function setDecisionLoading(loading: boolean): void {
  decisionRegion.setAttribute('aria-busy', String(loading));
  refreshButton.disabled = loading;
  refreshButton.classList.toggle('spinning', loading);
  newDecisionButton.disabled = loading;
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

function decisionStatusLabel(status: string): string {
  const labels: Record<string, string> = {
    draft: 'Черновик',
    proposed: 'Предложено',
    approved: 'Утверждено',
    rejected: 'Отклонено',
    superseded: 'Заменено',
  };
  return labels[status] ?? status;
}

function sensitivityLabel(level: string): string {
  const labels: Record<string, string> = {
    public: 'Публичная',
    internal: 'Внутренняя',
    confidential: 'Конфиденциальная',
    restricted: 'Ограниченная',
  };
  return labels[level] ?? level;
}

function relationLabel(relation: string): string {
  const labels: Record<string, string> = {
    references: 'Ссылается',
    derived_from: 'Основано на',
    depends_on: 'Зависит от',
    contradicts: 'Противоречит',
    explains: 'Объясняет',
    implements: 'Реализует',
    belongs_to: 'Принадлежит',
    supersedes: 'Заменяет',
  };
  return labels[relation] ?? relation;
}

function endpointLabel(type: string): string {
  const labels: Record<string, string> = {
    memory_object: 'Объект памяти',
    decision: 'Решение',
    open_question: 'Открытый вопрос',
    task: 'Задача',
    agent_run: 'Запуск агента',
  };
  return labels[type] ?? type;
}

function memoryTypeLabel(type: string): string {
  const labels: Record<string, string> = {
    document: 'Документ',
    protocol: 'Протокол',
    decision: 'Решение',
    research_result: 'Результат исследования',
    open_question: 'Открытый вопрос',
    ai_result: 'Результат AI',
    note: 'Заметка',
  };
  return labels[type] ?? type;
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
