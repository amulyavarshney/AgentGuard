package policy

import (
	"github.com/amulyavarshney/agentguard/internal/model"
)

// BaselineEngine applies deterministic MVP filesystem rules before delegating to Inner.
type BaselineEngine struct {
	Inner Engine
}

// NewBaselineEngine wraps an engine with filesystem baseline rules.
func NewBaselineEngine(inner Engine) BaselineEngine {
	if inner == nil {
		inner = StubEngine{}
	}
	return BaselineEngine{Inner: inner}
}

// Evaluate implements Engine.
func (b BaselineEngine) Evaluate(proposal model.ActionProposal) (EvaluationResult, error) {
	if d := baselineFilesystemDecision(proposal); d != "" {
		return EvaluationResult{
			Decision:     d,
			MatchedRules: []string{"baseline-filesystem"},
			PrimaryRule:  "baseline-filesystem",
		}, nil
	}
	return b.Inner.Evaluate(proposal)
}

func baselineFilesystemDecision(p model.ActionProposal) model.PolicyDecision {
	if p.ActionType != "filesystem" && p.ActionType != "shell" {
		return ""
	}
	raw := p.RawRequest
	if raw == nil {
		return ""
	}

	if touches, _ := raw["touches_backup"].(bool); touches {
		return model.PolicyBlock
	}

	outside, _ := raw["outside_allowlist"].(bool)
	fsAction, _ := raw["fs_action"].(string)
	recursive, _ := raw["recursive"].(bool)
	action, _ := raw["action"].(string)

	switch {
	case action == "rm_recursive" || (fsAction == "delete" && recursive):
		if outside {
			return model.PolicyBlock
		}
		return model.PolicyRequireApproval
	case fsAction == "delete" && outside:
		return model.PolicyBlock
	case fsAction == "overwrite" && outside:
		return model.PolicyRequireApproval
	case fsAction == "chmod" && outside:
		return model.PolicyRequireApproval
	case fsAction == "move" && outside:
		return model.PolicyRequireApproval
	default:
		return ""
	}
}

// NewCompositeEngine loads YAML policies when available and applies baseline filesystem rules.
func NewCompositeEngine(policyDir string) Engine {
	inner := Engine(StubEngine{})
	if eng, err := NewEngineFromDir(policyDir); err == nil {
		inner = eng
	}
	return NewBaselineEngine(inner)
}

// NewEngine is an alias for NewCompositeEngine.
func NewEngine(policyDir string) Engine {
	return NewCompositeEngine(policyDir)
}

// EvaluateProposal runs the engine and returns a typed decision.
func EvaluateProposal(engine Engine, proposal model.ActionProposal) (model.PolicyDecision, error) {
	result, err := EvaluateProposalDetailed(engine, proposal)
	if err != nil {
		return "", err
	}
	return result.Decision, nil
}

// EvaluateProposalDetailed returns the full evaluation result.
func EvaluateProposalDetailed(engine Engine, proposal model.ActionProposal) (EvaluationResult, error) {
	if engine == nil {
		engine = StubEngine{}
	}
	return engine.Evaluate(proposal)
}
