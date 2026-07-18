package policy

import (
	"path/filepath"
	"strings"

	"github.com/amulyavarshney/agentguard/internal/model"
)

// proposalContext carries optional scope fields used for learned-rule matching.
type proposalContext struct {
	AgentID string
	Repo    string
	Team    string
}

func contextFromProposal(p model.ActionProposal) proposalContext {
	ctx := proposalContext{}
	if p.ModelContext.Additional != nil {
		if v, ok := p.ModelContext.Additional["agent_id"].(string); ok {
			ctx.AgentID = v
		}
		if v, ok := p.ModelContext.Additional["repo"].(string); ok {
			ctx.Repo = v
		}
		if v, ok := p.ModelContext.Additional["team"].(string); ok {
			ctx.Team = v
		}
	}
	return ctx
}

func extractAction(p model.ActionProposal) string {
	if p.RawRequest != nil {
		if a, ok := p.RawRequest["action"].(string); ok && a != "" {
			return a
		}
		if a, ok := p.RawRequest["aws_action"].(string); ok && a != "" {
			return a
		}
	}
	return ""
}

func extractEgressBytes(p model.ActionProposal) int64 {
	if p.RawRequest == nil {
		return 0
	}
	switch v := p.RawRequest["egress_bytes"].(type) {
	case int:
		return int64(v)
	case int64:
		return v
	case float64:
		return int64(v)
	default:
		return 0
	}
}

func ruleMatchesScope(rule Rule, ctx proposalContext) bool {
	if rule.Scope == "" {
		return true
	}
	switch rule.Scope {
	case "agent":
		return rule.ScopeID == "" || rule.ScopeID == ctx.AgentID
	case "repo":
		return rule.ScopeID == "" || rule.ScopeID == ctx.Repo
	case "team":
		return rule.ScopeID == "" || rule.ScopeID == ctx.Team
	case "org":
		return true
	default:
		return true
	}
}

func ruleMatches(rule Rule, p model.ActionProposal) bool {
	if !ruleMatchesScope(rule, contextFromProposal(p)) {
		return false
	}
	m := rule.Match
	if m.Environment != "" && !strings.EqualFold(m.Environment, p.Environment) {
		return false
	}
	if len(m.ActionTypes) > 0 && !containsFold(m.ActionTypes, p.ActionType) {
		return false
	}
	action := extractAction(p)
	if len(m.Actions) > 0 {
		if action == "" || !containsFold(m.Actions, action) {
			return false
		}
	}
	if len(m.Resources) > 0 && !resourcesMatch(m.Resources, p.AffectedResources) {
		return false
	}
	if m.AffectedRecordsGT != nil && p.EstimatedBlastRadius <= *m.AffectedRecordsGT {
		return false
	}
	if m.EgressBytesGT != nil && extractEgressBytes(p) <= *m.EgressBytesGT {
		return false
	}
	if m.AgentID != "" && m.AgentID != contextFromProposal(p).AgentID {
		return false
	}
	if m.Repo != "" && m.Repo != contextFromProposal(p).Repo {
		return false
	}
	if m.Team != "" && m.Team != contextFromProposal(p).Team {
		return false
	}
	return matchCriteriaSpecified(m)
}

func matchCriteriaSpecified(m MatchCriteria) bool {
	return m.Environment != "" ||
		len(m.ActionTypes) > 0 ||
		len(m.Actions) > 0 ||
		len(m.Resources) > 0 ||
		m.AffectedRecordsGT != nil ||
		m.EgressBytesGT != nil ||
		m.AgentID != "" ||
		m.Repo != "" ||
		m.Team != ""
}

func containsFold(list []string, value string) bool {
	for _, item := range list {
		if strings.EqualFold(item, value) {
			return true
		}
	}
	return false
}

func resourcesMatch(patterns, resources []string) bool {
	if len(resources) == 0 {
		return false
	}
	for _, resource := range resources {
		for _, pattern := range patterns {
			if globMatch(pattern, resource) {
				return true
			}
		}
	}
	return false
}

func globMatch(pattern, value string) bool {
	pattern = strings.ToLower(pattern)
	value = strings.ToLower(value)
	ok, err := filepath.Match(pattern, value)
	if err == nil && ok {
		return true
	}
	if strings.Contains(value, strings.Trim(pattern, "*")) {
		return true
	}
	return false
}
