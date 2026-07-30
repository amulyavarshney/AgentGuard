import type {
  ApprovalRequest,
  AuditEvent,
  CredentialScopeEntry,
  PolicyDocument,
  PolicyEntry,
  RiskSummary,
  Session,
} from '../types'

export const demoSession: Session = {
  id: 'demo-session-staging-fix',
  task: 'Resolve a credential mismatch in staging.',
  environment: 'staging',
  status: 'ended',
  started_at: '2026-07-18T10:42:11Z',
  ended_at: '2026-07-18T10:42:31Z',
  agent_launcher: 'claude',
}

export const demoEvents: AuditEvent[] = [
  {
    id: 'evt-1',
    session_id: demoSession.id,
    sequence: 1,
    timestamp: '2026-07-18T10:42:26Z',
    proposal: {
      id: 'prop-1',
      session_id: demoSession.id,
      timestamp: '2026-07-18T10:42:23Z',
      intent_summary: demoSession.task,
      action_type: 'aws',
      command: 'aws rds delete-db-instance --db-instance-identifier prod-db',
      credential_ref: 'aws:prod-oncall',
      credential_scope: ['iam:write', 'rds:admin', 's3:full'],
      affected_resources: ['prod-db'],
      estimated_blast_radius: 50000,
      environment: 'production',
    },
    decision: 'block',
    result: 'blocked',
    side_effects: {
      matched_rule: 'rds-destructive',
      intent_aligned: false,
      intent_reasons: [
        'environment mismatch: task targets staging, action targets production',
        'destructive action conflicts with non-destructive task instruction',
      ],
    },
    prev_hash: '0000000000000000000000000000000000000000000000000000000000000000',
    event_hash: '45f3e3d20c1c0ccc67f15329c6a0836edd3290afabd0dbcfc2ea508833aa9044',
  },
]

export const demoApprovals: ApprovalRequest[] = []

export const demoPolicies: PolicyEntry[] = [
  {
    id: 'destructive-pack',
    source: 'default',
    file_path: 'policies/default/destructive-pack.yaml',
    enabled: true,
    rule_count: 12,
  },
  {
    id: 'learned-org-rds',
    source: 'learned',
    file_path: 'policies/learned/learned-org-aws-rds-delete.yaml',
    enabled: true,
    rule_count: 1,
  },
]

export const demoPolicyRules: PolicyDocument = {
  rules: [
    {
      id: 'rds-destructive',
      match: { action_types: ['aws'], actions: ['rds_delete_db_instance'] },
      require: { human_approval: true, approvers: 2 },
    },
  ],
}

export const demoRisk: RiskSummary = {
  by_decision: [
    { key: 'block', count: 12 },
    { key: 'require_approval', count: 4 },
    { key: 'allow', count: 40 },
    { key: 'pause_and_escalate', count: 2 },
  ],
  by_agent: [
    { key: 'claude', count: 18 },
    { key: 'npm-agent', count: 8 },
  ],
  by_repo: [
    { key: 'payments-api', count: 9 },
    { key: 'auth-service', count: 7 },
  ],
  by_rule: [
    { key: 'rds-destructive', count: 5 },
    { key: 'backup-protection', count: 3 },
    { key: 'mass-file-delete', count: 2 },
  ],
  total_events: 58,
}

export const demoCredentials: CredentialScopeEntry[] = [
  {
    ref: 'aws:prod-oncall',
    scope: ['iam:write', 'rds:admin', 's3:full', 'secrets:read'],
    last_used: '2026-07-18T10:42:20Z',
    usage_count: 14,
  },
  {
    ref: 'pg:staging-db',
    scope: ['db:read', 'db:write'],
    last_used: '2026-07-17T16:02:00Z',
    usage_count: 31,
  },
]
