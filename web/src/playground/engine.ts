/** Client-side policy + intent probe mirroring AgentGuard MVP rules (static playground). */

export type Decision = 'allow' | 'block' | 'require_approval' | 'pause_and_escalate'

export interface PlayAction {
  id: string
  label: string
  task: string
  command: string
  actionType: 'shell' | 'filesystem' | 'http' | 'postgres' | 'aws'
  action: string
  environment: string
  resources: string[]
  blastRadius: number
  egressBytes?: number
  credential: string
  credentialScope: string[]
}

export interface EvalResult {
  decision: Decision
  matchedRules: string[]
  intentAligned: boolean
  intentReasons: string[]
  summary: string
  timeline: { t: string; event: string; kind: 'info' | 'warn' | 'block' | 'ok' }[]
}

interface Rule {
  id: string
  match: {
    environment?: string
    action_types?: string[]
    actions?: string[]
    resources?: string[]
    affected_records_gt?: number
    egress_bytes_gt?: number
  }
  deny?: { agent_initiated_deletion?: boolean }
  require?: { human_approval?: boolean }
  action?: Decision
}

const RULES: Rule[] = [
  {
    id: 'production-database-destructive-actions',
    match: { environment: 'production', action_types: ['postgres'], actions: ['drop', 'truncate', 'bulk_delete'] },
    require: { human_approval: true },
  },
  {
    id: 'staging-database-destructive-actions',
    match: { environment: 'staging', action_types: ['postgres'], actions: ['drop', 'truncate', 'bulk_delete'] },
    require: { human_approval: true },
  },
  {
    id: 'backup-protection',
    match: { resources: ['*backup*', '*snapshot*'] },
    deny: { agent_initiated_deletion: true },
  },
  {
    id: 'backup-delete-aws',
    match: { action_types: ['aws'], actions: ['backup_delete', 'snapshot_delete', 'rds_delete_snapshot'] },
    deny: { agent_initiated_deletion: true },
  },
  {
    id: 'unusual-blast-radius',
    match: { affected_records_gt: 1000 },
    action: 'pause_and_escalate',
  },
  {
    id: 'iam-privilege-changes',
    match: {
      action_types: ['aws'],
      actions: ['iam_create_user', 'iam_delete_user', 'iam_attach_policy', 'iam_detach_policy'],
    },
    require: { human_approval: true },
  },
  {
    id: 'secret-exposure',
    match: {
      action_types: ['aws', 'http'],
      actions: ['secrets_get', 'credential_export', 'secret_rotation', 'secrets_manager_get'],
    },
    action: 'block',
  },
  {
    id: 'logging-disable',
    match: { action_types: ['aws'], actions: ['cloudtrail_stop', 'disable_logging'] },
    action: 'block',
  },
  {
    id: 'billing-changes',
    match: { action_types: ['aws'], actions: ['billing_modify', 'budget_delete'] },
    require: { human_approval: true },
  },
  {
    id: 'mass-file-delete',
    match: { action_types: ['filesystem', 'shell'], actions: ['rm_recursive', 'mass_delete', 'rm_rf'] },
    require: { human_approval: true },
  },
  {
    id: 'large-egress',
    match: { action_types: ['http'], egress_bytes_gt: 10485760 },
    action: 'pause_and_escalate',
  },
  {
    id: 'rds-destructive',
    match: { action_types: ['aws'], actions: ['rds_delete_db_instance', 'rds_delete_db_cluster'] },
    require: { human_approval: true },
  },
]

const RANK: Record<Decision, number> = {
  allow: 0,
  require_approval: 1,
  pause_and_escalate: 2,
  block: 3,
}

function globMatch(pattern: string, value: string): boolean {
  const re = new RegExp(
    '^' +
      pattern
        .replace(/[.+^${}()|[\]\\]/g, '\\$&')
        .replace(/\*/g, '.*')
        .replace(/\?/g, '.') +
      '$',
    'i',
  )
  return re.test(value)
}

function ruleMatches(rule: Rule, a: PlayAction): boolean {
  const m = rule.match
  if (m.environment && m.environment.toLowerCase() !== a.environment.toLowerCase()) return false
  if (m.action_types?.length && !m.action_types.some((t) => t.toLowerCase() === a.actionType.toLowerCase()))
    return false
  if (m.actions?.length && !m.actions.some((x) => x.toLowerCase() === a.action.toLowerCase())) return false
  if (m.resources?.length) {
    const ok = a.resources.some((r) => m.resources!.some((p) => globMatch(p, r)))
    if (!ok) return false
  }
  if (m.affected_records_gt != null && a.blastRadius <= m.affected_records_gt) return false
  if (m.egress_bytes_gt != null && (a.egressBytes ?? 0) <= m.egress_bytes_gt) return false
  return true
}

function ruleDecision(rule: Rule, a: PlayAction): Decision | null {
  if (!ruleMatches(rule, a)) return null
  if (rule.deny?.agent_initiated_deletion) {
    const deleting =
      /delete|rm_|drop|truncate|destroy/i.test(a.action) || /rm\s|delete/i.test(a.command)
    if (deleting) return 'block'
  }
  if (rule.require?.human_approval) return 'require_approval'
  if (rule.action) return rule.action
  return null
}

function compareIntent(a: PlayAction): { aligned: boolean; reasons: string[]; verdict: Decision | null } {
  const task = a.task.toLowerCase()
  const reasons: string[] = []
  let verdict: Decision | null = null

  const taskStaging = /\bstaging\b|\bstage\b/.test(task)
  const taskProd = /\bprod(uction)?\b/.test(task)
  const actionProd =
    a.environment === 'production' ||
    a.resources.some((r) => /prod/i.test(r)) ||
    /prod[-_]/i.test(a.command)

  if (taskStaging && actionProd) {
    reasons.push('environment mismatch: task targets staging, action targets production')
    verdict = 'pause_and_escalate'
  }

  const taskDestructive = /\b(delete|drop|destroy|truncate|wipe|rm\s+-rf)\b/.test(task)
  const actionDestructive =
    /delete|drop|truncate|rm_rf|rm_recursive|destroy|backup_delete|snapshot_delete/i.test(a.action)
  if (!taskDestructive && actionDestructive) {
    reasons.push('destructive action conflicts with non-destructive task instruction')
    verdict = 'block'
  }

  if (taskStaging && actionProd && actionDestructive) {
    reasons.push('destructive production action while task is scoped to non-production')
    verdict = 'block'
  }

  if (taskProd && a.environment === 'staging' && !actionProd) {
    // fine
  }

  void taskProd
  return { aligned: reasons.length === 0, reasons, verdict }
}

function strictest(a: Decision, b: Decision): Decision {
  return RANK[a] >= RANK[b] ? a : b
}

export function evaluateAction(a: PlayAction): EvalResult {
  let decision: Decision = 'allow'
  const matchedRules: string[] = []

  for (const rule of RULES) {
    const d = ruleDecision(rule, a)
    if (d) {
      matchedRules.push(rule.id)
      decision = strictest(decision, d)
    }
  }

  const intent = compareIntent(a)
  if (!intent.aligned && intent.verdict) {
    decision = strictest(decision, intent.verdict)
  }

  const timeline = [
    { t: '10:42:11', event: `Agent received task: “${a.task}”`, kind: 'info' as const },
    { t: '10:42:18', event: `Selected credential ${a.credential}`, kind: 'info' as const },
    {
      t: '10:42:20',
      event: `Credential scope: ${a.credentialScope.join(', ') || 'unknown'}`,
      kind: 'warn' as const,
    },
    { t: '10:42:23', event: `Proposed: ${a.command}`, kind: 'info' as const },
    {
      t: '10:42:24',
      event:
        matchedRules.length > 0
          ? `Policy matched: ${matchedRules.join(', ')}`
          : 'No hard policy match',
      kind: matchedRules.length ? ('warn' as const) : ('ok' as const),
    },
    {
      t: '10:42:25',
      event: intent.aligned
        ? 'Intent check: aligned with task'
        : `Intent check: ${intent.reasons[0]}`,
      kind: intent.aligned ? ('ok' as const) : ('warn' as const),
    },
    {
      t: '10:42:26',
      event:
        decision === 'allow'
          ? 'Allowed — executing real tool'
          : decision === 'block'
            ? 'Blocked — tool never invoked'
            : decision === 'require_approval'
              ? 'Paused — human approval required'
              : 'Paused — escalate to operator',
      kind: decision === 'allow' ? ('ok' as const) : ('block' as const),
    },
  ]

  const summary =
    decision === 'allow'
      ? 'Action would proceed under current policies.'
      : decision === 'block'
        ? 'Blocked before execution — no side effects on the target system.'
        : decision === 'require_approval'
          ? 'Held for human approval — not executed until an operator allows it.'
          : 'Paused and escalated — unusual blast radius or risk signal.'

  return {
    decision,
    matchedRules,
    intentAligned: intent.aligned,
    intentReasons: intent.reasons,
    summary,
    timeline,
  }
}

export function decisionLabel(d: Decision): string {
  switch (d) {
    case 'allow':
      return 'Allow'
    case 'block':
      return 'Block'
    case 'require_approval':
      return 'Require approval'
    case 'pause_and_escalate':
      return 'Pause & escalate'
  }
}
