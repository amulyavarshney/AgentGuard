package adapters_test

import (
	"context"
	"testing"

	"github.com/amulyavarshney/agentguard/internal/adapters"
	"github.com/amulyavarshney/agentguard/internal/model"
)

func TestAWSAdapterRDSDestroy(t *testing.T) {
	t.Parallel()
	adapter := adapters.NewAWSAdapter()
	proposal, err := adapter.Classify(context.Background(), map[string]any{
		"tool":        "aws",
		"argv":        []string{"--profile", "prod-oncall", "rds", "delete-db-instance", "--db-instance-identifier", "prod-db"},
		"environment": "staging",
		"session_id":  "sess-aws",
	})
	if err != nil {
		t.Fatalf("classify: %v", err)
	}
	if proposal.ActionType != "aws" {
		t.Fatalf("action_type = %q", proposal.ActionType)
	}
	if proposal.RawRequest["action"] != "rds_delete_db_instance" {
		t.Fatalf("action = %v", proposal.RawRequest["action"])
	}
	if proposal.RawRequest["profile"] != "prod-oncall" {
		t.Fatalf("profile = %v", proposal.RawRequest["profile"])
	}

	engine := loadDefaultEngine(t)
	result, err := engine.Evaluate(proposal)
	if err != nil {
		t.Fatal(err)
	}
	if result.Decision != model.PolicyRequireApproval {
		t.Fatalf("decision = %q, want require_approval", result.Decision)
	}
}

func TestAWSAdapterIAMAttachPolicy(t *testing.T) {
	t.Parallel()
	adapter := adapters.NewAWSAdapter()
	proposal, err := adapter.Classify(context.Background(), map[string]any{
		"tool": "aws",
		"argv": []string{"iam", "attach-user-policy", "--user-name", "agent", "--policy-arn", "arn:aws:iam::123:policy/Admin"},
	})
	if err != nil {
		t.Fatalf("classify: %v", err)
	}
	if proposal.RawRequest["action"] != "iam_attach_policy" {
		t.Fatalf("action = %v", proposal.RawRequest["action"])
	}
}

func TestAWSAdapterSecretsManagerGet(t *testing.T) {
	t.Parallel()
	adapter := adapters.NewAWSAdapter()
	proposal, err := adapter.Classify(context.Background(), map[string]any{
		"tool": "aws",
		"argv": []string{"secretsmanager", "get-secret-value", "--secret-id", "prod/api-key"},
	})
	if err != nil {
		t.Fatalf("classify: %v", err)
	}
	if proposal.RawRequest["action"] != "secrets_manager_get" {
		t.Fatalf("action = %v", proposal.RawRequest["action"])
	}

	engine := loadDefaultEngine(t)
	result, err := engine.Evaluate(proposal)
	if err != nil {
		t.Fatal(err)
	}
	if result.Decision != model.PolicyBlock {
		t.Fatalf("decision = %q, want block", result.Decision)
	}
}

func TestAWSAdapterCloudTrailStop(t *testing.T) {
	t.Parallel()
	adapter := adapters.NewAWSAdapter()
	proposal, err := adapter.Classify(context.Background(), map[string]any{
		"tool": "aws",
		"argv": []string{"cloudtrail", "stop-logging", "--name", "org-trail"},
	})
	if err != nil {
		t.Fatalf("classify: %v", err)
	}
	if proposal.RawRequest["action"] != "cloudtrail_stop" {
		t.Fatalf("action = %v", proposal.RawRequest["action"])
	}

	engine := loadDefaultEngine(t)
	result, err := engine.Evaluate(proposal)
	if err != nil {
		t.Fatal(err)
	}
	if result.Decision != model.PolicyBlock {
		t.Fatalf("decision = %q, want block", result.Decision)
	}
}

func TestAWSAdapterS3Delete(t *testing.T) {
	t.Parallel()
	adapter := adapters.NewAWSAdapter()
	proposal, err := adapter.Classify(context.Background(), map[string]any{
		"tool": "aws",
		"argv": []string{"s3", "rm", "s3://bucket/key"},
	})
	if err != nil {
		t.Fatalf("classify: %v", err)
	}
	if proposal.RawRequest["action"] != "s3_delete" {
		t.Fatalf("action = %v", proposal.RawRequest["action"])
	}
}

func TestAWSAdapterSnapshotDeleteBlocked(t *testing.T) {
	t.Parallel()
	adapter := adapters.NewAWSAdapter()
	proposal, err := adapter.Classify(context.Background(), map[string]any{
		"tool": "aws",
		"argv": []string{"rds", "delete-db-snapshot", "--db-snapshot-identifier", "prod-snap"},
	})
	if err != nil {
		t.Fatalf("classify: %v", err)
	}
	if proposal.RawRequest["action"] != "snapshot_delete" {
		t.Fatalf("action = %v", proposal.RawRequest["action"])
	}

	engine := loadDefaultEngine(t)
	result, err := engine.Evaluate(proposal)
	if err != nil {
		t.Fatal(err)
	}
	if result.Decision != model.PolicyBlock {
		t.Fatalf("decision = %q, want block", result.Decision)
	}
}

func TestAWSGoldenCases(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		argv   []string
		action string
	}{
		{"budget delete", []string{"budgets", "delete-budget", "--account-id", "123", "--budget-name", "monthly"}, "budget_delete"},
		{"rotate secret", []string{"secretsmanager", "rotate-secret", "--secret-id", "x"}, "secret_rotation"},
		{"ce anomaly", []string{"ce", "create-anomaly-monitor", "--anomaly-monitor", "x"}, "ce_create_anomaly_monitor"},
		{"s3api delete", []string{"s3api", "delete-object", "--bucket", "b", "--key", "k"}, "s3_delete"},
	}
	adapter := adapters.NewAWSAdapter()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			proposal, err := adapter.Classify(context.Background(), map[string]any{
				"tool": "aws",
				"argv": tc.argv,
			})
			if err != nil {
				t.Fatalf("classify: %v", err)
			}
			if proposal.RawRequest["action"] != tc.action {
				t.Fatalf("action = %v, want %s", proposal.RawRequest["action"], tc.action)
			}
		})
	}
}
