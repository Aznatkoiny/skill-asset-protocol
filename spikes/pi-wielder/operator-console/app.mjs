const viewNames = Object.freeze(['overview', 'policies', 'approvals', 'receipts']);
const launchMatch = /^#launch=([A-Za-z0-9_-]{43})$/.exec(window.location.hash);
let launchToken = launchMatch?.[1] ?? null;
history.replaceState(null, '', `${window.location.pathname}${window.location.search}`);

let csrfToken = null;
let validatedPolicy = null;

const byId = (id) => document.getElementById(id);

function canonicalIdForPath(value) {
  if (typeof value !== 'string'
      || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$/.test(value)) {
    throw new TypeError('Operator identifier is outside the canonical path grammar');
  }
  return value;
}

function canonicalJson(value, ancestors = new Set()) {
  if (value === null) return 'null';
  if (typeof value === 'string') return JSON.stringify(value);
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'number' && Number.isSafeInteger(value) && !Object.is(value, -0)) {
    return String(value);
  }
  if (!value || typeof value !== 'object' || ancestors.has(value)) {
    throw new TypeError('Operator request must contain inert canonical JSON data');
  }
  ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      if (Object.getPrototypeOf(value) !== Array.prototype
          || Object.keys(value).length !== value.length) {
        throw new TypeError('Operator request array is not dense canonical data');
      }
      return `[${value.map((element) => canonicalJson(element, ancestors)).join(',')}]`;
    }
    if (Object.getPrototypeOf(value) !== Object.prototype) {
      throw new TypeError('Operator request object is not canonical data');
    }
    const fields = [];
    for (const key of Reflect.ownKeys(value).sort()) {
      if (typeof key !== 'string') throw new TypeError('Operator request key is invalid');
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor?.enumerable || !Object.hasOwn(descriptor, 'value')) {
        throw new TypeError('Operator request object must contain only data fields');
      }
      fields.push(`${JSON.stringify(key)}:${canonicalJson(descriptor.value, ancestors)}`);
    }
    return `{${fields.join(',')}}`;
  } finally {
    ancestors.delete(value);
  }
}

function setMessage(message, state = 'neutral') {
  const element = byId('console-message');
  element.textContent = message;
  element.dataset.state = state;
}

function setText(id, value) {
  byId(id).textContent = value === null || value === undefined || value === '' ? '—' : String(value);
}

function addRecord(container, label, value) {
  const row = document.createElement('div');
  const key = document.createElement('span');
  const output = document.createElement('strong');
  key.textContent = label;
  output.textContent = value === null || value === undefined ? '—' : String(value);
  row.append(key, output);
  container.append(row);
}

function clear(element) {
  while (element.firstChild) element.firstChild.remove();
}

function renderRecord(id, record, preferred = []) {
  const container = byId(id);
  clear(container);
  if (!record || typeof record !== 'object') {
    addRecord(container, 'State', 'No record');
    return;
  }
  const keys = preferred.length > 0
    ? preferred.filter((key) => Object.hasOwn(record, key))
    : Object.keys(record).slice(0, 12);
  for (const key of keys) {
    const value = record[key];
    addRecord(container, key, value && typeof value === 'object' ? JSON.stringify(value) : value);
  }
}

async function api(path, { method = 'GET', body } = {}) {
  const headers = { accept: 'application/json' };
  if (body !== undefined) headers['content-type'] = 'application/json';
  if (method !== 'GET') {
    if (!csrfToken) throw new Error('LOCAL_SESSION_REQUIRED');
    headers['x-csrf-token'] = csrfToken;
  }
  const response = await fetch(path, {
    method,
    headers,
    body: body === undefined ? undefined : canonicalJson(body),
    credentials: 'same-origin',
    redirect: 'error',
    referrerPolicy: 'no-referrer',
  });
  if (response.status === 204) return null;
  const value = await response.json();
  if (!response.ok || value?.ok !== true || !Object.hasOwn(value, 'data')) {
    throw new Error(value?.error?.code ?? 'OPERATOR_REQUEST_FAILED');
  }
  return value.data;
}

async function exchangeLaunch() {
  if (!launchToken) return false;
  const body = canonicalJson({ launchToken });
  launchToken = null;
  const response = await fetch('/operator/v1/session', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body,
    credentials: 'same-origin',
    redirect: 'error',
    referrerPolicy: 'no-referrer',
  });
  if (response.status !== 204) throw new Error('LAUNCH_EXCHANGE_FAILED');
  csrfToken = response.headers.get('x-csrf-token');
  if (!/^[A-Za-z0-9_-]{43}$/.test(csrfToken ?? '')) throw new Error('CSRF_MISSING');
  return true;
}

function renderOverview(value) {
  setText('wallet-network', value.wallet?.network);
  setText('wallet-address', value.wallet?.address);
  setText('agent-state', value.agent?.state);
  setText('spend-gate', value.health?.admission);
  setText('session-ceiling', value.budget?.sessionMaxAtomic);
  setText('available-budget', value.budget?.availableAtomic);
  setText('reserved-budget', value.budget?.reservedAtomic);
  setText('unresolved-budget', value.budget?.unresolvedAtomic);
  renderRecord('enrollment-summary', value.agent);
  if (value.agent?.state === 'active'
      && value.agent.agentInstanceId && value.agent.enrollmentHash) {
    byId('enrollment-summary').append(actionButton('Revoke agent access', async () => {
      if (!window.confirm('Revoke this agent credential now? Existing unresolved value remains blocked for operator recovery.')) return;
      try {
        await api(`/operator/v1/agents/${canonicalIdForPath(value.agent.agentInstanceId)}/revoke`, {
          method: 'POST',
          body: { expectedEnrollmentHash: value.agent.enrollmentHash },
        });
        await loadOverview();
        setMessage('Agent access revoked. Reconcile and close retained sessions before replacement.', 'ready');
      } catch {
        setMessage('Agent revocation failed. Refresh the enrollment hash and try again.', 'error');
      }
    }));
  }
  renderRecord('health-summary', value.health);
  const feed = byId('evidence-feed');
  clear(feed);
  for (const event of value.recentEvidence ?? []) {
    const item = document.createElement('li');
    const time = document.createElement('time');
    const summary = document.createElement('span');
    time.textContent = event.at ?? '—';
    summary.textContent = event.summary ?? event.state ?? 'Wallet event';
    item.append(time, summary);
    feed.append(item);
  }
}

function renderPolicies(value) {
  renderRecord('active-policy', value.active, ['id', 'hash', 'network', 'wallet', 'defaultAction']);
  const history = byId('policy-history');
  clear(history);
  for (const policy of value.history ?? []) {
    addRecord(history, policy.id ?? 'Policy', policy.hash ?? '—');
  }
  const sessions = byId('policy-sessions');
  clear(sessions);
  const targetPolicyHash = value.active?.hash ?? value.active?.policyHash;
  for (const session of value.sessions ?? value.blockedSessions ?? []) {
    const card = document.createElement('article');
    card.className = 'decision-card';
    const title = document.createElement('h3');
    title.textContent = `${session.state ?? 'Session'} · ${session.id ?? '—'}`;
    card.append(title);
    for (const key of ['policyVersionId', 'state', 'sessionHash', 'reservedAtomic', 'unresolvedAtomic']) {
      if (Object.hasOwn(session, key)) addRecord(card, key, session[key]);
    }
    const actions = document.createElement('div');
    actions.className = 'action-row';
    if (session.state === 'policy_blocked' && targetPolicyHash && session.sessionHash) {
      actions.append(actionButton('Transition to active policy', async () => {
        if (!window.confirm('Transition this blocked session to the displayed active policy after all blockers have been checked?')) return;
        try {
          await api(`/operator/v1/sessions/${canonicalIdForPath(session.id)}/transition-policy`, {
            method: 'POST',
            body: { targetPolicyHash, expectedSessionHash: session.sessionHash },
          });
          await loadPolicies();
          setMessage('Session transitioned to the active policy.', 'ready');
        } catch {
          setMessage('Session transition failed. Refresh its hash and blockers.', 'error');
        }
      }));
    }
    if (session.sessionHash) {
      actions.append(actionButton('Close session', async () => {
        if (!window.confirm('Close this session? No replacement session is created automatically.')) return;
        try {
          await api(`/operator/v1/sessions/${canonicalIdForPath(session.id)}/close`, {
            method: 'POST', body: { expectedSessionHash: session.sessionHash },
          });
          await loadPolicies();
          setMessage('Session closed. Agent access now requires explicit reconfiguration.', 'ready');
        } catch {
          setMessage('Session close is blocked. Resolve reserved or unresolved value first.', 'error');
        }
      }));
    }
    card.append(actions);
    sessions.append(card);
  }
}

function actionButton(label, action) {
  const button = document.createElement('button');
  button.type = 'button';
  button.textContent = label;
  button.addEventListener('click', action);
  return button;
}

function renderApprovals(value) {
  const list = byId('approval-list');
  clear(list);
  for (const approval of value.items ?? value.approvals ?? []) {
    const card = document.createElement('article');
    card.className = 'decision-card';
    const title = document.createElement('h3');
    title.textContent = `${approval.purposeLabel ?? 'Spend request'} · ${approval.amountAtomic ?? '—'}`;
    card.append(title);
    for (const key of ['sellerOrigin', 'resourcePath', 'requestHash', 'purposeLabel', 'amountAtomic', 'wallet', 'reasonCode', 'expiresAt', 'intentHash']) {
      if (Object.hasOwn(approval, key)) addRecord(card, key, approval[key]);
    }
    const actions = document.createElement('div');
    actions.className = 'action-row';
    actions.append(
      actionButton('Approve once', async () => {
        if (!window.confirm(`Approve request ${approval.requestHash} to ${approval.sellerOrigin}${approval.resourcePath} for at most ${approval.amountAtomic}?`)) return;
        await api(`/operator/v1/approvals/${canonicalIdForPath(approval.id)}/approve`, {
          method: 'POST', body: { expectedIntentHash: approval.intentHash },
        });
        await loadApprovals();
      }),
      actionButton('Deny', async () => {
        if (!window.confirm('Deny this exact request? The agent must submit a new request to try again.')) return;
        await api(`/operator/v1/approvals/${canonicalIdForPath(approval.id)}/deny`, {
          method: 'POST',
          body: { expectedIntentHash: approval.intentHash, reasonCode: 'OPERATOR_DENIED' },
        });
        await loadApprovals();
      }),
    );
    card.append(actions);
    list.append(card);
  }
}

function renderReceipts(value) {
  const list = byId('receipt-list');
  clear(list);
  for (const receipt of value.items ?? value.receipts ?? []) {
    const card = document.createElement('article');
    card.className = 'decision-card';
    const title = document.createElement('h3');
    title.textContent = `${receipt.terminalState ?? 'Unresolved'} · ${receipt.id ?? 'Receipt'}`;
    card.append(title);
    const reconciliation = receipt.reconciliation ?? receipt;
    for (const key of ['hash', 'sellerOrigin', 'chargedAtomic', 'terminalState', 'intentHash', 'caseHash', 'reasonCode']) {
      if (Object.hasOwn(receipt, key)) addRecord(card, key === 'caseHash' ? 'case hash' : key, receipt[key]);
    }
    const localBinding = reconciliation.localBinding ?? reconciliation.binding ?? {};
    for (const key of [
      'resourcePath',
      'requestHash',
      'wallet',
      'policyVersionId',
      'policyHash',
      'amountAtomic',
      'authorizationNonce',
      'transactionId',
      'originalTransactionId',
      'refundSource',
    ]) {
      const displayValue = Object.hasOwn(localBinding, key)
        ? localBinding[key]
        : reconciliation[key];
      if (displayValue !== undefined) addRecord(card, key, displayValue);
    }
    const kind = reconciliation.kind;
    const intentId = reconciliation.intentId;
    const expectedIntentHash = reconciliation.intentHash ?? receipt.intentHash;
    const expectedCaseHash = reconciliation.caseHash ?? receipt.caseHash;
    if (['payment', 'execution', 'refund-observation'].includes(kind)
        && intentId && expectedIntentHash && expectedCaseHash) {
      const actions = document.createElement('div');
      actions.className = 'action-row';
      let transactionInput = null;
      if (kind === 'payment' || kind === 'refund-observation') {
        transactionInput = document.createElement('input');
        transactionInput.type = 'text';
        transactionInput.maxLength = 66;
        transactionInput.autocomplete = 'off';
        transactionInput.spellcheck = false;
        transactionInput.placeholder = kind === 'payment'
          ? 'Optional payment transaction ID'
          : 'Required refund transaction ID';
        transactionInput.setAttribute('aria-label', transactionInput.placeholder);
        actions.append(transactionInput);
      }
      actions.append(actionButton('Reconcile displayed case', async () => {
        if (!window.confirm(`Reconcile only the displayed ${kind} case hash?`)) return;
        const body = { expectedIntentHash, expectedCaseHash };
        const candidate = transactionInput?.value ?? '';
        if (kind === 'payment' && candidate !== '') body.paymentTransactionId = candidate;
        if (kind === 'refund-observation') body.refundTransactionId = candidate;
        try {
          await api(`/operator/v1/reconciliations/${canonicalIdForPath(intentId)}/${kind}`, {
            method: 'POST', body,
          });
          await loadReceipts();
          setMessage('Reconciliation observation completed. Review the revised signed receipt.', 'ready');
        } catch {
          setMessage('Reconciliation did not resolve. Refresh the case before another observation.', 'error');
        }
      }));
      if ((kind === 'payment' || kind === 'refund-observation')
          && reconciliation.candidate?.state === 'pending') {
        actions.append(actionButton('Abandon candidate', async () => {
          if (!window.confirm('Abandon this candidate? The hold remains and only a fresh case hash can name a replacement.')) return;
          try {
            await api(`/operator/v1/reconciliations/${canonicalIdForPath(intentId)}/${kind}/abandon-candidate`, {
              method: 'POST', body: { expectedIntentHash, expectedCaseHash },
            });
            await loadReceipts();
            setMessage('Candidate abandoned. The value hold remains under a fresh case hash.', 'ready');
          } catch {
            setMessage('Candidate abandonment failed. Refresh the case hash.', 'error');
          }
        }));
      }
      card.append(actions);
    }
    list.append(card);
  }
}

async function loadOverview() { renderOverview(await api('/operator/v1/overview')); }
async function loadPolicies() { renderPolicies(await api('/operator/v1/policies')); }
async function loadApprovals() { renderApprovals(await api('/operator/v1/approvals')); }
async function loadReceipts() { renderReceipts(await api('/operator/v1/receipts')); }

const loaders = Object.freeze({
  overview: loadOverview,
  policies: loadPolicies,
  approvals: loadApprovals,
  receipts: loadReceipts,
});

async function showView(name) {
  if (!viewNames.includes(name)) return;
  for (const candidate of viewNames) {
    const selected = candidate === name;
    byId(`view-${candidate}`).hidden = !selected;
    byId(`view-${candidate}`).classList.toggle('is-active', selected);
    document.querySelector(`[data-view="${candidate}"]`).classList.toggle('is-active', selected);
  }
  try {
    await loaders[name]();
    setMessage(`${name[0].toUpperCase()}${name.slice(1)} is current.`, 'ready');
  } catch (error) {
    setMessage(error.message === 'OPERATOR_UNAUTHORIZED'
      ? 'This local session ended. Open a fresh console launch link.'
      : `Could not refresh ${name}.`, 'error');
  }
}

for (const button of document.querySelectorAll('[data-view]')) {
  button.addEventListener('click', () => showView(button.dataset.view));
}
for (const button of document.querySelectorAll('[data-refresh]')) {
  button.addEventListener('click', () => showView(button.dataset.refresh));
}

byId('validate-policy').addEventListener('click', async () => {
  const file = byId('policy-file').files?.[0];
  if (!file || file.size > 65_536) {
    setMessage('Choose one policy JSON file no larger than 64 KiB.', 'error');
    return;
  }
  try {
    const document = JSON.parse(await file.text());
    validatedPolicy = await api('/operator/v1/policies/validate', {
      method: 'POST', body: { document },
    });
    renderRecord('policy-validation', validatedPolicy, ['policyHash', 'policy']);
    byId('apply-policy').disabled = false;
    setMessage('Policy validated. Confirm the displayed hash before applying.', 'ready');
  } catch {
    validatedPolicy = null;
    byId('apply-policy').disabled = true;
    setMessage('Policy validation failed. Check the closed policy schema.', 'error');
  }
});

byId('apply-policy').addEventListener('click', async () => {
  if (!validatedPolicy) return;
  const file = byId('policy-file').files?.[0];
  if (!file) return;
  try {
    const document = JSON.parse(await file.text());
    await api('/operator/v1/policies/apply', {
      method: 'POST', body: { document, expectedPolicyHash: validatedPolicy.policyHash },
    });
    validatedPolicy = null;
    byId('apply-policy').disabled = true;
    await loadPolicies();
    setMessage('Policy applied. Blocked sessions remain visibly blocked.', 'ready');
  } catch {
    setMessage('Policy apply failed. Revalidate the current file and wallet.', 'error');
  }
});

byId('end-session').addEventListener('click', async () => {
  try {
    await api('/operator/v1/session', { method: 'DELETE' });
  } finally {
    csrfToken = null;
    setMessage('Local session ended. Open a fresh console launch link.', 'neutral');
  }
});

try {
  if (await exchangeLaunch()) {
    byId('authority-status').textContent = 'Local session active';
    await showView('overview');
  }
} catch {
  csrfToken = null;
  setMessage('The console launch link is invalid or expired. Request a fresh link.', 'error');
}
