package policy_test

import (
	"testing"

	"github.com/amulyavarshney/agentguard/internal/model"
	"github.com/amulyavarshney/agentguard/internal/policy"
)

func TestBaselineEngineBlocksRecursiveDeleteOutsideAllowlist(t *testing.T) {
	t.Parallel()

	engine := policy.NewBaselineEngine(policy.StubEngine{})
	result, err := engine.Evaluate(model.ActionProposal{
		ActionType: "filesystem",
		RawRequest: map[string]any{
			"fs_action":         "delete",
			"recursive":         true,
			"outside_allowlist": true,
			"action":            "rm_recursive",
		},
	})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if result.Decision != model.PolicyBlock {
		t.Fatalf("decision = %q, want block", result.Decision)
	}
}

func TestBaselineEngineRequiresApprovalForRecursiveDeleteInAllowlist(t *testing.T) {
	t.Parallel()

	engine := policy.NewBaselineEngine(policy.StubEngine{})
	result, err := engine.Evaluate(model.ActionProposal{
		ActionType: "filesystem",
		RawRequest: map[string]any{
			"fs_action":         "delete",
			"recursive":         true,
			"outside_allowlist": false,
			"action":            "rm_recursive",
		},
	})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if result.Decision != model.PolicyRequireApproval {
		t.Fatalf("decision = %q, want require_approval", result.Decision)
	}
}

func TestBaselineEngineBlocksBackupDeletion(t *testing.T) {
	t.Parallel()

	engine := policy.NewBaselineEngine(policy.StubEngine{})
	result, err := engine.Evaluate(model.ActionProposal{
		ActionType: "filesystem",
		RawRequest: map[string]any{
			"touches_backup": true,
		},
	})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if result.Decision != model.PolicyBlock {
		t.Fatalf("decision = %q, want block", result.Decision)
	}
}

func TestBaselineEngineDelegatesToInnerWhenNoBaselineMatch(t *testing.T) {
	t.Parallel()

	engine := policy.NewBaselineEngine(policy.StubEngine{})
	result, err := engine.Evaluate(model.ActionProposal{
		ActionType: "http",
		Command:    "GET /health",
	})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if result.Decision != model.PolicyAllow {
		t.Fatalf("decision = %q, want allow", result.Decision)
	}
}
