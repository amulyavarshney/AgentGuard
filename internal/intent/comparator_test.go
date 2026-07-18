package intent_test

import (
	"testing"
	"time"

	"github.com/amulyavarshney/agentguard/internal/intent"
	"github.com/amulyavarshney/agentguard/internal/model"
)

func TestStagingFixVsProdDBDeleteBlocked(t *testing.T) {
	t.Parallel()

	cmp := intent.NewHeuristicComparator()
	task := "fix auth error in staging"
	proposal := model.ActionProposal{
		ID:            "prop-1",
		SessionID:     "sess-1",
		Timestamp:     time.Now().UTC(),
		IntentSummary: task,
		ActionType:    "shell",
		Command:       `bash -c 'aws rds delete-db-instance --db-instance-identifier prod-db'`,
		Environment:   "staging",
		AffectedResources: []string{
			"prod-db",
		},
		RawRequest: map[string]any{
			"tool": "bash",
			"argv": []string{"-c", "aws rds delete-db-instance --db-instance-identifier prod-db"},
		},
	}

	result, err := cmp.Compare(task, proposal)
	if err != nil {
		t.Fatalf("compare: %v", err)
	}
	if result.Aligned {
		t.Fatal("expected misaligned intent for staging fix vs prod-db delete")
	}
	if result.Verdict != model.PolicyBlock {
		t.Fatalf("verdict = %q, want block", result.Verdict)
	}
	if len(result.Reasons) == 0 {
		t.Fatal("expected at least one mismatch reason")
	}
}

func TestAlignedStagingReadOnlyAction(t *testing.T) {
	t.Parallel()

	cmp := intent.NewHeuristicComparator()
	task := "fix auth error in staging"
	proposal := model.ActionProposal{
		ActionType:  "shell",
		Command:     "aws logs describe-log-groups --log-group-name-prefix staging-auth",
		Environment: "staging",
	}

	result, err := cmp.Compare(task, proposal)
	if err != nil {
		t.Fatalf("compare: %v", err)
	}
	if !result.Aligned {
		t.Fatalf("expected aligned intent, got reasons: %v", result.Reasons)
	}
}

func TestDestructiveActionAgainstNonDestructiveTask(t *testing.T) {
	t.Parallel()

	cmp := intent.NewHeuristicComparator()
	task := "investigate slow queries in staging"
	proposal := model.ActionProposal{
		ActionType: "filesystem",
		Command:    "rm -rf /tmp/cache",
		Environment: "staging",
		RawRequest: map[string]any{
			"fs_action": "delete",
			"recursive": true,
		},
	}

	result, err := cmp.Compare(task, proposal)
	if err != nil {
		t.Fatalf("compare: %v", err)
	}
	if result.Aligned {
		t.Fatal("expected misaligned intent for investigate task vs rm")
	}
	if result.Verdict != model.PolicyBlock {
		t.Fatalf("verdict = %q, want block", result.Verdict)
	}
}

func TestResourceOutsideDeclaredScope(t *testing.T) {
	t.Parallel()

	cmp := intent.NewHeuristicComparator()
	task := "update staging-auth-service configuration"
	proposal := model.ActionProposal{
		ActionType:        "shell",
		Command:           "kubectl rollout restart deployment billing-service",
		Environment:       "staging",
		AffectedResources: []string{"billing-service"},
	}

	result, err := cmp.Compare(task, proposal)
	if err != nil {
		t.Fatalf("compare: %v", err)
	}
	if result.Aligned {
		t.Fatal("expected resource scope mismatch")
	}
	if result.Verdict != model.PolicyRequireApproval {
		t.Fatalf("verdict = %q, want require_approval", result.Verdict)
	}
}

func TestEmptyTaskAllowsAnyAction(t *testing.T) {
	t.Parallel()

	cmp := intent.NewHeuristicComparator()
	proposal := model.ActionProposal{
		ActionType: "shell",
		Command:    "aws rds delete-db-instance --db-instance-identifier prod-db",
		Environment: "production",
	}

	result, err := cmp.Compare("", proposal)
	if err != nil {
		t.Fatalf("compare: %v", err)
	}
	if !result.Aligned {
		t.Fatalf("empty task should skip intent checks, got reasons: %v", result.Reasons)
	}
}

func TestStubComparatorAlwaysAligned(t *testing.T) {
	t.Parallel()

	cmp := intent.StubComparator{}
	result, err := cmp.Compare("fix staging", model.ActionProposal{
		Command: "aws rds delete-db-instance --db-instance-identifier prod-db",
	})
	if err != nil {
		t.Fatalf("compare: %v", err)
	}
	if !result.Aligned {
		t.Fatal("stub comparator should always align")
	}
}
