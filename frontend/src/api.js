const BASE = '/api';

async function req(path, { method = 'GET', body } = {}) {
  const r = await fetch(BASE + path, {
    method,
    headers: body ? { 'Content-Type': 'application/json' } : undefined,
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await r.text();
  const data = text ? JSON.parse(text) : null;
  if (!r.ok) throw new Error(data?.detail || `${r.status} ${r.statusText}`);
  return data;
}

export const api = {
  listPolicies: () => req('/policies'),
  getPolicy: (id) => req(`/policies/${id}`),
  createPolicy: (b) => req('/policies', { method: 'POST', body: b }),
  setRules: (id, rules, default_action) =>
    req(`/policies/${id}/rules`, { method: 'PUT', body: { rules, default_action } }),
  analyze: (id) => req(`/policies/${id}/analyze`),
  classify: (id, prefix) =>
    req(`/policies/${id}/classify`, { method: 'POST', body: { prefix } }),
  batch: (id, probes) =>
    req(`/policies/${id}/classify/batch`, { method: 'POST', body: { probes } }),
  trie: (id) => req(`/policies/${id}/trie`),
  snapshots: (id) => req(`/policies/${id}/snapshots`),
  snapshot: (id, label, created_by = 'lab') =>
    req(`/policies/${id}/snapshots`, { method: 'POST', body: { label, created_by } }),
  getSnapshot: (id) => req(`/snapshots/${id}`),
  diff: (a, b) => req('/snapshots/diff', { method: 'POST', body: { old_snapshot_id: a, new_snapshot_id: b } }),
  replay: (id, probes) =>
    req(`/snapshots/${id}/replay`, { method: 'POST', body: { probes } }),
  scenarios: () => req('/scenarios'),
  scenario: (id) => req(`/scenarios/${id}`),
  replayScenario: (id) => req(`/scenarios/${id}/replay`, { method: 'POST' }),
  neighbors: () => req('/neighbors'),
  frrStatus: () => req('/frr/status'),
  crossValidate: (id, probes, node = 'a') =>
    req(`/snapshots/${id}/cross-validate`, { method: 'POST', body: { probes, node } }),
  runs: () => req('/runs'),

  // time-bounded exceptions
  publishBaseline: (id, label = '', created_by = 'lab') =>
    req(`/policies/${id}/baseline/publish`, { method: 'POST', body: { label, created_by } }),
  getBaseline: (id) => req(`/policies/${id}/baseline`),
  listExceptions: (pid) => req(`/policies/${pid}/exceptions`),
  createException: (pid, body) =>
    req(`/policies/${pid}/exceptions`, { method: 'POST', body }),
  getException: (id) => req(`/exceptions/${id}`),
  patchException: (id, body) =>
    req(`/exceptions/${id}`, { method: 'PATCH', body }),
  deleteException: (id) =>
    req(`/exceptions/${id}`, { method: 'DELETE' }),
  exAction: (id, action, body = {}) =>
    req(`/exceptions/${id}/${action}`, { method: 'POST', body }),
  exHistory: (id) => req(`/exceptions/${id}/history`),
  exPreview: (id, baseline_snapshot_id) =>
    req(`/exceptions/${id}/preview` +
      (baseline_snapshot_id ? `?baseline_snapshot_id=${baseline_snapshot_id}` : '')),
  effective: (pid, at) =>
    req(`/policies/${pid}/effective` + (at ? `?at=${encodeURIComponent(at)}` : '')),
  effectiveClassify: (pid, prefix, at) =>
    req(`/policies/${pid}/effective/classify`, { method: 'POST', body: { prefix, at } }),
  effectiveCrossValidate: (pid, probes, node, at) =>
    req(`/policies/${pid}/effective/cross-validate`,
      { method: 'POST', body: { probes, node, at } }),
  timeline: (pid, at) =>
    req(`/policies/${pid}/timeline` + (at ? `?at=${encodeURIComponent(at)}` : '')),
  tick: (at) => req('/exceptions/tick', { method: 'POST', body: { at } }),
  clock: () => req('/clock'),
  clockFreeze: (at) => req('/clock/freeze', { method: 'POST', body: { at } }),
  clockAdvance: (seconds, at) =>
    req('/clock/advance', { method: 'POST', body: { seconds, at } }),
  clockReset: () => req('/clock/reset', { method: 'POST' }),
};
