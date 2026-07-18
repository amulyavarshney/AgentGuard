package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/amulyavarshney/agentguard/internal/model"
	"github.com/google/uuid"
	"gopkg.in/yaml.v3"
)

// SaveLearnedRule persists an intervention as a permanent YAML rule under policies/learned/.
func SaveLearnedRule(policyDir string, input SaveRuleInput) (string, error) {
	if err := validateSaveInput(input); err != nil {
		return "", err
	}

	rule := buildLearnedRule(input)
	doc := Document{Rules: []Rule{rule}}

	dir := filepath.Join(policyDir, "learned")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("create learned policy dir: %w", err)
	}

	filename := fmt.Sprintf("%s.yaml", rule.ID)
	path := filepath.Join(dir, filename)
	data, err := yaml.Marshal(doc)
	if err != nil {
		return "", fmt.Errorf("marshal learned rule: %w", err)
	}

	header := fmt.Sprintf("# Learned rule from intervention (scope=%s/%s)\n# Created: %s\n",
		input.Scope, input.ScopeID, time.Now().UTC().Format(time.RFC3339))
	if err := os.WriteFile(path, append([]byte(header), data...), 0o644); err != nil {
		return "", fmt.Errorf("write learned rule: %w", err)
	}
	return path, nil
}

func validateSaveInput(input SaveRuleInput) error {
	if input.Scope == "" {
		return fmt.Errorf("scope is required")
	}
	if _, ok := validScopes[input.Scope]; !ok {
		return fmt.Errorf("invalid scope %q (must be agent, repo, team, or org)", input.Scope)
	}
	if input.Scope != "org" && input.ScopeID == "" {
		return fmt.Errorf("scope_id is required for scope %q", input.Scope)
	}
	if input.Decision != model.PolicyBlock && input.Decision != model.PolicyRequireApproval {
		return fmt.Errorf("decision must be block or require_approval for learned rules")
	}
	if input.Proposal.ActionType == "" {
		return fmt.Errorf("proposal action_type is required")
	}
	return nil
}

func buildLearnedRule(input SaveRuleInput) Rule {
	action := extractAction(input.Proposal)
	slug := slugify(input.Proposal.ActionType)
	if action != "" {
		slug = slug + "-" + slugify(action)
	}
	id := fmt.Sprintf("learned-%s-%s-%s", input.Scope, slug, uuid.New().String()[:8])

	match := MatchCriteria{
		ActionTypes: []string{input.Proposal.ActionType},
	}
	if action != "" {
		match.Actions = []string{action}
	}
	if len(input.Proposal.AffectedResources) > 0 && input.Scope != "org" {
		match.Resources = append([]string{}, input.Proposal.AffectedResources...)
	}
	// Org-scoped learned rules apply across all environments (org-wide for MVP).
	if input.Proposal.Environment != "" && input.Scope != "org" {
		match.Environment = input.Proposal.Environment
	}

	switch input.Scope {
	case "agent":
		match.AgentID = input.ScopeID
	case "repo":
		match.Repo = input.ScopeID
	case "team":
		match.Team = input.ScopeID
	}

	rule := Rule{
		ID:      id,
		Scope:   input.Scope,
		ScopeID: input.ScopeID,
		Match:   match,
		Meta: map[string]any{
			"source_session": input.SessionID,
			"reason":         input.Reason,
			"created_at":     time.Now().UTC().Format(time.RFC3339),
			"source_command": input.Proposal.Command,
		},
	}

	switch input.Decision {
	case model.PolicyBlock:
		rule.Action = string(model.PolicyBlock)
	case model.PolicyRequireApproval:
		rule.Require = RequireClause{HumanApproval: true, Approvers: 1}
	default:
		rule.Action = string(input.Decision)
	}
	return rule
}

func slugify(s string) string {
	s = strings.ToLower(s)
	var b strings.Builder
	lastDash := false
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			lastDash = false
			continue
		}
		if !lastDash {
			b.WriteRune('-')
			lastDash = true
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return "action"
	}
	return out
}
