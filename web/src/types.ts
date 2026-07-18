export type PolicyDecision = 'allow' | 'block' | 'require_approval' | 'pause_and_escalate'

export interface Session {
  id: string
  task?: string
  environment?: string
  status: 'active' | 'ended' | 'pending'
  started_at: string
  ended_at?: string
  agent_launcher?: string
}

export interface ActionProposal {
  id: string
  session_id: string
  timestamp: string
  intent_summary?: string
  action_type: string
  command: string
  credential_ref?: string
  credential_scope?: string[]
  affected_resources?: string[]
  estimated_blast_radius?: number
  environment?: string
}

export interface AuditEvent {
  id: string
  session_id: string
  sequence: number
  timestamp: string
  proposal: ActionProposal
  decision: PolicyDecision
  approvers?: string[]
  result?: string
  side_effects?: Record<string, unknown>
  prev_hash: string
  event_hash: string
}

export interface ApprovalRequest {
  id: string
  session_id: string
  proposal: ActionProposal
  decision: PolicyDecision
  created_at: string
  status: string
}

export interface PolicyEntry {
  id: string
  source: 'default' | 'learned'
  file_path: string
  enabled: boolean
  rule_count: number
}

export interface PolicyDocument {
  rules: Array<{
    id: string
    match?: Record<string, unknown>
    require?: Record<string, unknown>
    deny?: Record<string, unknown>
    action?: string
  }>
}

export interface RiskBucket {
  key: string
  count: number
}

export interface RiskSummary {
  by_agent: RiskBucket[]
  by_repo: RiskBucket[]
  by_rule: RiskBucket[]
  by_decision: RiskBucket[]
  total_events: number
}

export interface CredentialScopeEntry {
  ref: string
  scope: string[]
  last_used: string
  usage_count: number
}
