package model

import "time"

// ModelContext captures model and prompt references available at decision time.
type ModelContext struct {
	Model      string         `json:"model,omitempty"`
	SessionID  string         `json:"session_id,omitempty"`
	PromptRef  string         `json:"prompt_ref,omitempty"`
	Additional map[string]any `json:"additional,omitempty"`
}

// ActionProposal is the normalized schema for every gated action.
type ActionProposal struct {
	ID                   string         `json:"id"`
	SessionID            string         `json:"session_id"`
	Timestamp            time.Time      `json:"timestamp"`
	IntentSummary        string         `json:"intent_summary,omitempty"`
	ActionType           string         `json:"action_type"`
	Command              string         `json:"command"`
	RawRequest           map[string]any `json:"raw_request,omitempty"`
	CredentialRef        string         `json:"credential_ref,omitempty"`
	CredentialScope      []string       `json:"credential_scope,omitempty"`
	AffectedResources    []string       `json:"affected_resources,omitempty"`
	EstimatedBlastRadius int            `json:"estimated_blast_radius,omitempty"`
	Environment          string         `json:"environment,omitempty"`
	ModelContext         ModelContext   `json:"model_context,omitempty"`
}

// PolicyDecision is the outcome of policy evaluation.
type PolicyDecision string

const (
	PolicyAllow            PolicyDecision = "allow"
	PolicyBlock              PolicyDecision = "block"
	PolicyRequireApproval    PolicyDecision = "require_approval"
	PolicyPauseAndEscalate   PolicyDecision = "pause_and_escalate"
)

// Valid reports whether d is a known policy decision value.
func (d PolicyDecision) Valid() bool {
	switch d {
	case PolicyAllow, PolicyBlock, PolicyRequireApproval, PolicyPauseAndEscalate:
		return true
	default:
		return false
	}
}

// AuditEvent is an append-only, hash-chained audit record.
type AuditEvent struct {
	ID          string         `json:"id"`
	SessionID   string         `json:"session_id"`
	Sequence    int64          `json:"sequence"`
	Timestamp   time.Time      `json:"timestamp"`
	Proposal    ActionProposal `json:"proposal"`
	Decision    PolicyDecision `json:"decision"`
	Approvers   []string       `json:"approvers,omitempty"`
	Result      string         `json:"result,omitempty"`
	SideEffects map[string]any `json:"side_effects,omitempty"`
	PrevHash    string         `json:"prev_hash"`
	EventHash   string         `json:"event_hash"`
}
