import type {
  ApprovalRequest,
  AuditEvent,
  CredentialScopeEntry,
  PolicyDocument,
  PolicyEntry,
  RiskSummary,
  Session,
} from '../types'

const BASE = '/api/v1'

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    headers: { 'Content-Type': 'application/json', ...init?.headers },
    ...init,
  })
  if (!res.ok) {
    const body = await res.json().catch(() => ({}))
    throw new Error(body.error ?? `HTTP ${res.status}`)
  }
  return res.json() as Promise<T>
}

export const api = {
  health: () => fetch('/health').then((r) => r.json()),

  sessions: () => request<Session[]>('/sessions'),
  session: (id: string) => request<Session>(`/sessions/${id}`),
  sessionEvents: (id: string) => request<AuditEvent[]>(`/sessions/${id}/events`),

  events: (params?: { decision?: string; limit?: number }) => {
    const q = new URLSearchParams()
    if (params?.decision) q.set('decision', params.decision)
    if (params?.limit) q.set('limit', String(params.limit))
    const qs = q.toString()
    return request<AuditEvent[]>(`/events${qs ? `?${qs}` : ''}`)
  },

  approvals: () => request<ApprovalRequest[]>('/approvals'),
  approve: (id: string) =>
    request<{ status: string; request: ApprovalRequest }>(`/approvals/${id}/approve`, {
      method: 'POST',
    }),
  deny: (id: string) =>
    request<{ status: string; request: ApprovalRequest }>(`/approvals/${id}/deny`, {
      method: 'POST',
    }),
  saveAsRule: (id: string, body: { scope?: string; rule_id?: string }) =>
    request<{ status: string; rule_id: string; file_path: string }>(
      `/approvals/${id}/save-as-rule`,
      { method: 'POST', body: JSON.stringify(body) },
    ),

  policies: () => request<PolicyEntry[]>('/policies'),
  policyRules: (id: string) => request<PolicyDocument>(`/policies/${id}/rules`),
  setPolicyEnabled: (id: string, enabled: boolean) =>
    request<{ id: string; enabled: boolean }>(`/policies/${id}`, {
      method: 'PATCH',
      body: JSON.stringify({ enabled }),
    }),

  riskSummary: () => request<RiskSummary>('/risk/summary'),
  credentialScopes: () => request<CredentialScopeEntry[]>('/credentials/scopes'),
}
