package policy

import "github.com/amulyavarshney/agentguard/internal/model"

// Document is the top-level YAML policy file structure.
type Document struct {
	Rules []Rule `yaml:"rules"`
}

// Rule describes a single policy rule.
type Rule struct {
	ID      string         `yaml:"id"`
	Scope   string         `yaml:"scope,omitempty"`
	ScopeID string         `yaml:"scope_id,omitempty"`
	Match   MatchCriteria  `yaml:"match,omitempty"`
	Require RequireClause  `yaml:"require,omitempty"`
	Deny    DenyClause     `yaml:"deny,omitempty"`
	Action  string         `yaml:"action,omitempty"`
	Meta    map[string]any `yaml:"meta,omitempty"`
}

// MatchCriteria defines when a rule applies to an ActionProposal.
type MatchCriteria struct {
	Environment         string   `yaml:"environment,omitempty"`
	ActionTypes         []string `yaml:"action_types,omitempty"`
	Actions             []string `yaml:"actions,omitempty"`
	Resources           []string `yaml:"resources,omitempty"`
	AffectedRecordsGT   *int     `yaml:"affected_records_gt,omitempty"`
	EgressBytesGT       *int64   `yaml:"egress_bytes_gt,omitempty"`
	AgentID             string   `yaml:"agent_id,omitempty"`
	Repo                string   `yaml:"repo,omitempty"`
	Team                string   `yaml:"team,omitempty"`
}

// RequireClause specifies approval requirements when a rule matches.
type RequireClause struct {
	HumanApproval  bool `yaml:"human_approval,omitempty"`
	Approvers      int  `yaml:"approvers,omitempty"`
	BackupVerified bool `yaml:"backup_verified,omitempty"`
}

// DenyClause specifies hard denial conditions.
type DenyClause struct {
	AgentInitiatedDeletion bool `yaml:"agent_initiated_deletion,omitempty"`
}

// EvaluationResult is the outcome of policy evaluation with metadata.
type EvaluationResult struct {
	Decision     model.PolicyDecision `json:"decision"`
	MatchedRules []string             `json:"matched_rules,omitempty"`
	PrimaryRule  string               `json:"primary_rule,omitempty"`
	Require      *RequireClause       `json:"require,omitempty"`
}

// SaveRuleInput captures intervention context for persisting a learned rule.
type SaveRuleInput struct {
	Proposal  model.ActionProposal `json:"proposal"`
	Scope     string               `json:"scope"`
	ScopeID   string               `json:"scope_id"`
	Decision  model.PolicyDecision `json:"decision"`
	Reason    string               `json:"reason,omitempty"`
	SessionID string               `json:"session_id,omitempty"`
}
