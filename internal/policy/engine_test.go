package policy

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/amulyavarshney/agentguard/internal/model"
)

func testProposal(opts func(*model.ActionProposal)) model.ActionProposal {
	p := model.ActionProposal{
		ID:        "prop-1",
		SessionID: "sess-1",
		Timestamp: time.Now(),
		ActionType: "shell",
		Command:   "echo hello",
	}
	if opts != nil {
		opts(&p)
	}
	return p
}

func loadDefaultEngine(t *testing.T) *DefaultEngine {
	t.Helper()
	dir := filepath.Join("..", "..", "policies")
	engine, err := NewEngineFromDefaultDir(dir)
	if err != nil {
		t.Fatalf("NewEngineFromDefaultDir: %v", err)
	}
	return engine
}

func TestProductionDatabaseDestructiveRequiresApproval(t *testing.T) {
	engine := loadDefaultEngine(t)
	result, err := engine.Evaluate(testProposal(func(p *model.ActionProposal) {
		p.Environment = "production"
		p.ActionType = "postgres"
		p.RawRequest = map[string]any{"action": "drop"}
		p.Command = "DROP TABLE users"
	}))
	if err != nil {
		t.Fatal(err)
	}
	if result.Decision != model.PolicyRequireApproval {
		t.Fatalf("decision = %q, want require_approval", result.Decision)
	}
	if result.Require == nil || result.Require.Approvers != 2 || !result.Require.BackupVerified {
		t.Fatalf("require clause = %+v, want 2 approvers + backup_verified", result.Require)
	}
}

func TestStagingDatabaseDestructiveRequiresOneApprover(t *testing.T) {
	engine := loadDefaultEngine(t)
	result, err := engine.Evaluate(testProposal(func(p *model.ActionProposal) {
		p.Environment = "staging"
		p.ActionType = "postgres"
		p.RawRequest = map[string]any{"action": "truncate"}
	}))
	if err != nil {
		t.Fatal(err)
	}
	if result.Decision != model.PolicyRequireApproval {
		t.Fatalf("decision = %q, want require_approval", result.Decision)
	}
	if result.Require == nil || result.Require.Approvers != 1 {
		t.Fatalf("require approvers = %d, want 1", result.Require.Approvers)
	}
}

func TestBackupProtectionBlocksDeletion(t *testing.T) {
	engine := loadDefaultEngine(t)
	result, err := engine.Evaluate(testProposal(func(p *model.ActionProposal) {
		p.ActionType = "filesystem"
		p.RawRequest = map[string]any{"action": "delete"}
		p.AffectedResources = []string{"/data/nightly-backup.tar.gz"}
	}))
	if err != nil {
		t.Fatal(err)
	}
	if result.Decision != model.PolicyBlock {
		t.Fatalf("decision = %q, want block", result.Decision)
	}
}

func TestBackupDeleteAWSBlocked(t *testing.T) {
	engine := loadDefaultEngine(t)
	result, err := engine.Evaluate(testProposal(func(p *model.ActionProposal) {
		p.ActionType = "aws"
		p.RawRequest = map[string]any{"action": "snapshot_delete"}
		p.Command = "aws rds delete-db-snapshot --db-snapshot-identifier prod-snap"
	}))
	if err != nil {
		t.Fatal(err)
	}
	if result.Decision != model.PolicyBlock {
		t.Fatalf("decision = %q, want block", result.Decision)
	}
}

func TestUnusualBlastRadiusPauseAndEscalate(t *testing.T) {
	engine := loadDefaultEngine(t)
	result, err := engine.Evaluate(testProposal(func(p *model.ActionProposal) {
		p.ActionType = "postgres"
		p.RawRequest = map[string]any{"action": "bulk_delete"}
		p.EstimatedBlastRadius = 5000
	}))
	if err != nil {
		t.Fatal(err)
	}
	if result.Decision != model.PolicyPauseAndEscalate {
		t.Fatalf("decision = %q, want pause_and_escalate", result.Decision)
	}
}

func TestBlastRadiusBelowThresholdAllows(t *testing.T) {
	engine := loadDefaultEngine(t)
	result, err := engine.Evaluate(testProposal(func(p *model.ActionProposal) {
		p.ActionType = "postgres"
		p.RawRequest = map[string]any{"action": "select"}
		p.EstimatedBlastRadius = 50
	}))
	if err != nil {
		t.Fatal(err)
	}
	if result.Decision != model.PolicyAllow {
		t.Fatalf("decision = %q, want allow", result.Decision)
	}
}

func TestIAMPrivilegeChangesRequireApproval(t *testing.T) {
	engine := loadDefaultEngine(t)
	result, err := engine.Evaluate(testProposal(func(p *model.ActionProposal) {
		p.ActionType = "aws"
		p.RawRequest = map[string]any{"action": "iam_attach_policy"}
		p.Command = "aws iam attach-user-policy --user-name agent --policy-arn arn:aws:iam::123:policy/Admin"
	}))
	if err != nil {
		t.Fatal(err)
	}
	if result.Decision != model.PolicyRequireApproval {
		t.Fatalf("decision = %q, want require_approval", result.Decision)
	}
	if result.Require == nil || result.Require.Approvers != 2 {
		t.Fatalf("require approvers = %d, want 2", result.Require.Approvers)
	}
}

func TestSecretExposureBlocked(t *testing.T) {
	engine := loadDefaultEngine(t)
	result, err := engine.Evaluate(testProposal(func(p *model.ActionProposal) {
		p.ActionType = "aws"
		p.RawRequest = map[string]any{"action": "secrets_get"}
	}))
	if err != nil {
		t.Fatal(err)
	}
	if result.Decision != model.PolicyBlock {
		t.Fatalf("decision = %q, want block", result.Decision)
	}
}

func TestSecretRotationBlocked(t *testing.T) {
	engine := loadDefaultEngine(t)
	result, err := engine.Evaluate(testProposal(func(p *model.ActionProposal) {
		p.ActionType = "aws"
		p.RawRequest = map[string]any{"action": "secret_rotation"}
	}))
	if err != nil {
		t.Fatal(err)
	}
	if result.Decision != model.PolicyBlock {
		t.Fatalf("decision = %q, want block", result.Decision)
	}
}

func TestLoggingDisableBlocked(t *testing.T) {
	engine := loadDefaultEngine(t)
	result, err := engine.Evaluate(testProposal(func(p *model.ActionProposal) {
		p.ActionType = "aws"
		p.RawRequest = map[string]any{"action": "cloudtrail_stop"}
	}))
	if err != nil {
		t.Fatal(err)
	}
	if result.Decision != model.PolicyBlock {
		t.Fatalf("decision = %q, want block", result.Decision)
	}
}

func TestBillingChangesRequireApproval(t *testing.T) {
	engine := loadDefaultEngine(t)
	result, err := engine.Evaluate(testProposal(func(p *model.ActionProposal) {
		p.ActionType = "aws"
		p.RawRequest = map[string]any{"action": "budget_delete"}
	}))
	if err != nil {
		t.Fatal(err)
	}
	if result.Decision != model.PolicyRequireApproval {
		t.Fatalf("decision = %q, want require_approval", result.Decision)
	}
}

func TestMassFileDeleteRequiresApproval(t *testing.T) {
	engine := loadDefaultEngine(t)
	result, err := engine.Evaluate(testProposal(func(p *model.ActionProposal) {
		p.ActionType = "shell"
		p.RawRequest = map[string]any{"action": "rm_recursive"}
		p.Command = "rm -rf /tmp/project"
	}))
	if err != nil {
		t.Fatal(err)
	}
	if result.Decision != model.PolicyRequireApproval {
		t.Fatalf("decision = %q, want require_approval", result.Decision)
	}
}

func TestLargeEgressPauseAndEscalate(t *testing.T) {
	engine := loadDefaultEngine(t)
	result, err := engine.Evaluate(testProposal(func(p *model.ActionProposal) {
		p.ActionType = "http"
		p.RawRequest = map[string]any{"egress_bytes": int64(20 * 1024 * 1024)}
	}))
	if err != nil {
		t.Fatal(err)
	}
	if result.Decision != model.PolicyPauseAndEscalate {
		t.Fatalf("decision = %q, want pause_and_escalate", result.Decision)
	}
}

func TestLargeEgressBelowThresholdAllows(t *testing.T) {
	engine := loadDefaultEngine(t)
	result, err := engine.Evaluate(testProposal(func(p *model.ActionProposal) {
		p.ActionType = "http"
		p.RawRequest = map[string]any{"egress_bytes": int64(1024)}
	}))
	if err != nil {
		t.Fatal(err)
	}
	if result.Decision != model.PolicyAllow {
		t.Fatalf("decision = %q, want allow", result.Decision)
	}
}

func TestBlockWinsOverRequireApproval(t *testing.T) {
	engine := NewDefaultEngine([]Rule{
		{
			ID: "require-rule",
			Match: MatchCriteria{
				ActionTypes: []string{"aws"},
				Actions:     []string{"snapshot_delete"},
			},
			Require: RequireClause{HumanApproval: true},
		},
		{
			ID: "block-rule",
			Match: MatchCriteria{
				Resources: []string{"*backup*"},
			},
			Deny: DenyClause{AgentInitiatedDeletion: true},
		},
	})
	result, err := engine.Evaluate(testProposal(func(p *model.ActionProposal) {
		p.ActionType = "aws"
		p.RawRequest = map[string]any{"action": "snapshot_delete"}
		p.AffectedResources = []string{"prod-backup-2024"}
	}))
	if err != nil {
		t.Fatal(err)
	}
	if result.Decision != model.PolicyBlock {
		t.Fatalf("decision = %q, want block (strictest wins)", result.Decision)
	}
	if len(result.MatchedRules) != 2 {
		t.Fatalf("matched %d rules, want 2", len(result.MatchedRules))
	}
}

func TestLearnedRuleScopeAgent(t *testing.T) {
	engine := NewDefaultEngine([]Rule{
		{
			ID:      "learned-agent-block",
			Scope:   "agent",
			ScopeID: "claude-code",
			Match: MatchCriteria{
				ActionTypes: []string{"aws"},
				Actions:     []string{"rds_delete_db_instance"},
				AgentID:     "claude-code",
			},
			Action: string(model.PolicyBlock),
		},
	})

	blocked, err := engine.Evaluate(testProposal(func(p *model.ActionProposal) {
		p.ActionType = "aws"
		p.RawRequest = map[string]any{"action": "rds_delete_db_instance"}
		p.ModelContext.Additional = map[string]any{"agent_id": "claude-code"}
	}))
	if err != nil {
		t.Fatal(err)
	}
	if blocked.Decision != model.PolicyBlock {
		t.Fatalf("same agent: decision = %q, want block", blocked.Decision)
	}

	allowed, err := engine.Evaluate(testProposal(func(p *model.ActionProposal) {
		p.ActionType = "aws"
		p.RawRequest = map[string]any{"action": "rds_delete_db_instance"}
		p.ModelContext.Additional = map[string]any{"agent_id": "other-agent"}
	}))
	if err != nil {
		t.Fatal(err)
	}
	if allowed.Decision != model.PolicyAllow {
		t.Fatalf("other agent: decision = %q, want allow", allowed.Decision)
	}
}

func TestValidateDocumentRejectsInvalidAction(t *testing.T) {
	err := ValidateDocument(Document{Rules: []Rule{
		{ID: "bad", Action: "nuke", Match: MatchCriteria{ActionTypes: []string{"shell"}}},
	}})
	if err == nil {
		t.Fatal("expected validation error for invalid action")
	}
}

func TestValidateDocumentRequiresEffect(t *testing.T) {
	err := ValidateDocument(Document{Rules: []Rule{
		{ID: "no-effect", Match: MatchCriteria{ActionTypes: []string{"shell"}}},
	}})
	if err == nil {
		t.Fatal("expected validation error for missing effect")
	}
}

func TestValidateFileDefaultPack(t *testing.T) {
	path := filepath.Join("..", "..", "policies", "default", "destructive-pack.yaml")
	if err := ValidateFile(path); err != nil {
		t.Fatalf("default pack invalid: %v", err)
	}
}

func TestSaveLearnedRule(t *testing.T) {
	dir := t.TempDir()
	path, err := SaveLearnedRule(dir, SaveRuleInput{
		Proposal: testProposal(func(p *model.ActionProposal) {
			p.Environment = "production"
			p.ActionType = "aws"
			p.RawRequest = map[string]any{"action": "rds_delete_db_instance"}
			p.Command = "aws rds delete-db-instance --db-instance-identifier prod-db"
		}),
		Scope:     "org",
		ScopeID:   "default",
		Decision:  model.PolicyBlock,
		Reason:    "human denied prod RDS delete",
		SessionID: "sess-demo",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateFile(path); err != nil {
		t.Fatalf("learned rule invalid: %v", err)
	}
	engine, err := NewEngineFromDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	result, err := engine.Evaluate(testProposal(func(p *model.ActionProposal) {
		p.Environment = "production"
		p.ActionType = "aws"
		p.RawRequest = map[string]any{"action": "rds_delete_db_instance"}
	}))
	if err != nil {
		t.Fatal(err)
	}
	if result.Decision != model.PolicyBlock {
		t.Fatalf("after learned rule: decision = %q, want block", result.Decision)
	}
}

func TestResourceGlobEdgeCases(t *testing.T) {
	tests := []struct {
		pattern string
		value   string
		want    bool
	}{
		{"*backup*", "s3://bucket/nightly-backup", true},
		{"*snapshot*", "rds:prod-snapshot-01", true},
		{"*backup*", "s3://bucket/data.csv", false},
	}
	for _, tc := range tests {
		if got := globMatch(tc.pattern, tc.value); got != tc.want {
			t.Errorf("globMatch(%q, %q) = %v, want %v", tc.pattern, tc.value, got, tc.want)
		}
	}
}
