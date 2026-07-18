package policy

import (
	"fmt"
	"path/filepath"

	"github.com/amulyavarshney/agentguard/internal/model"
)

// Engine evaluates policies against action proposals.
type Engine interface {
	Evaluate(proposal model.ActionProposal) (EvaluationResult, error)
}

// DefaultEngine evaluates a loaded rule set deterministically.
type DefaultEngine struct {
	rules []Rule
}

// NewDefaultEngine constructs an engine from explicit rules.
func NewDefaultEngine(rules []Rule) *DefaultEngine {
	cp := make([]Rule, len(rules))
	copy(cp, rules)
	return &DefaultEngine{rules: cp}
}

// NewEngineFromDir loads policies from policyDir/default and policyDir/learned.
func NewEngineFromDir(policyDir string) (*DefaultEngine, error) {
	rules, err := LoadFromDir(policyDir, nil)
	if err != nil {
		return nil, err
	}
	return NewDefaultEngine(rules), nil
}

// NewEngineFromDefaultDir loads only shipped baseline packs under policyDir/default.
func NewEngineFromDefaultDir(policyDir string) (*DefaultEngine, error) {
	rules, err := LoadFromDir(filepath.Join(policyDir, "default"), nil)
	if err != nil {
		return nil, err
	}
	return NewDefaultEngine(rules), nil
}

// Evaluate implements Engine.
func (e *DefaultEngine) Evaluate(proposal model.ActionProposal) (EvaluationResult, error) {
	if e == nil {
		return EvaluationResult{Decision: model.PolicyAllow}, nil
	}

	var matched []string
	var require *RequireClause
	decision := model.PolicyAllow
	primary := ""

	for _, rule := range e.rules {
		if !ruleMatches(rule, proposal) {
			continue
		}
		matched = append(matched, rule.ID)
		ruleDecision, ruleRequire := ruleEffect(rule)
		if ruleRequire != nil && (require == nil || ruleRequire.Approvers > require.Approvers) {
			cp := *ruleRequire
			require = &cp
		}
		if decisionStrictness(ruleDecision) > decisionStrictness(decision) {
			decision = ruleDecision
			primary = rule.ID
		}
	}

	if len(matched) == 0 {
		return EvaluationResult{Decision: model.PolicyAllow}, nil
	}

	return EvaluationResult{
		Decision:     decision,
		MatchedRules: matched,
		PrimaryRule:  primary,
		Require:      require,
	}, nil
}

func ruleEffect(rule Rule) (model.PolicyDecision, *RequireClause) {
	if rule.Deny.AgentInitiatedDeletion {
		return model.PolicyBlock, nil
	}
	if rule.Action != "" {
		switch model.PolicyDecision(rule.Action) {
		case model.PolicyAllow, model.PolicyBlock, model.PolicyRequireApproval, model.PolicyPauseAndEscalate:
			if rule.Action == string(model.PolicyRequireApproval) || rule.Require.HumanApproval {
				req := rule.Require
				if !rule.Require.HumanApproval {
					req.HumanApproval = true
				}
				return model.PolicyRequireApproval, &req
			}
			return model.PolicyDecision(rule.Action), nil
		default:
			return model.PolicyAllow, nil
		}
	}
	if rule.Require.HumanApproval {
		req := rule.Require
		return model.PolicyRequireApproval, &req
	}
	return model.PolicyAllow, nil
}

func decisionStrictness(d model.PolicyDecision) int {
	switch d {
	case model.PolicyBlock:
		return 4
	case model.PolicyPauseAndEscalate:
		return 3
	case model.PolicyRequireApproval:
		return 2
	case model.PolicyAllow:
		return 1
	default:
		return 0
	}
}

// StrictestDecision returns the more restrictive of two policy decisions.
func StrictestDecision(a, b model.PolicyDecision) model.PolicyDecision {
	if decisionStrictness(b) > decisionStrictness(a) {
		return b
	}
	return a
}

// StubEngine always returns allow (deprecated; use DefaultEngine).
type StubEngine struct{}

// Evaluate implements Engine.
func (StubEngine) Evaluate(_ model.ActionProposal) (EvaluationResult, error) {
	return EvaluationResult{Decision: model.PolicyAllow}, nil
}

// DecisionString returns the decision string for callers expecting legacy string API.
func DecisionString(r EvaluationResult) string {
	return string(r.Decision)
}

// EvaluateString is a compatibility helper returning decision as string.
func EvaluateString(engine Engine, proposal model.ActionProposal) (string, error) {
	r, err := engine.Evaluate(proposal)
	if err != nil {
		return "", err
	}
	if !r.Decision.Valid() {
		return "", fmt.Errorf("invalid policy decision: %q", r.Decision)
	}
	return string(r.Decision), nil
}
