package adapters_test

import (
	"context"
	"testing"

	"github.com/amulyavarshney/agentguard/internal/adapters"
	"github.com/amulyavarshney/agentguard/internal/model"
)

func TestPostgresAdapterDropTable(t *testing.T) {
	t.Parallel()
	adapter := adapters.NewPostgresAdapter()
	proposal, err := adapter.Classify(context.Background(), map[string]any{
		"tool":        "psql",
		"argv":        []string{"-h", "db.prod.example.com", "-U", "admin", "-d", "app", "-c", "DROP TABLE users;"},
		"session_id":  "sess-pg",
		"environment": "staging",
		"task":        "inspect schema",
	})
	if err != nil {
		t.Fatalf("classify: %v", err)
	}
	if proposal.ActionType != "postgres" {
		t.Fatalf("action_type = %q", proposal.ActionType)
	}
	if proposal.RawRequest["action"] != "drop" {
		t.Fatalf("action = %v", proposal.RawRequest["action"])
	}
	if proposal.RawRequest["host"] != "db.prod.example.com" {
		t.Fatalf("host = %v", proposal.RawRequest["host"])
	}
	if proposal.RawRequest["destructive"] != true {
		t.Fatalf("destructive = %v", proposal.RawRequest["destructive"])
	}

	engine := loadDefaultEngine(t)
	result, err := engine.Evaluate(proposal)
	if err != nil {
		t.Fatal(err)
	}
	// staging env + drop => require_approval (not production)
	if result.Decision != model.PolicyRequireApproval {
		t.Fatalf("decision = %q, want require_approval", result.Decision)
	}
}

func TestPostgresAdapterTruncate(t *testing.T) {
	t.Parallel()
	adapter := adapters.NewPostgresAdapter()
	proposal, err := adapter.Classify(context.Background(), map[string]any{
		"tool": "psql",
		"argv": []string{"-c", "TRUNCATE TABLE events;"},
	})
	if err != nil {
		t.Fatalf("classify: %v", err)
	}
	if proposal.RawRequest["action"] != "truncate" {
		t.Fatalf("action = %v", proposal.RawRequest["action"])
	}
	if proposal.EstimatedBlastRadius < 1000 {
		t.Fatalf("blast radius = %d", proposal.EstimatedBlastRadius)
	}
}

func TestPostgresAdapterBulkDeleteWithoutWhere(t *testing.T) {
	t.Parallel()
	adapter := adapters.NewPostgresAdapter()
	proposal, err := adapter.Classify(context.Background(), map[string]any{
		"tool": "psql",
		"argv": []string{"-c", "DELETE FROM sessions;"},
	})
	if err != nil {
		t.Fatalf("classify: %v", err)
	}
	if proposal.RawRequest["action"] != "bulk_delete" {
		t.Fatalf("action = %v", proposal.RawRequest["action"])
	}
	if proposal.EstimatedBlastRadius != 10000 {
		t.Fatalf("blast radius = %d", proposal.EstimatedBlastRadius)
	}
}

func TestPostgresAdapterSelectAllowed(t *testing.T) {
	t.Parallel()
	adapter := adapters.NewPostgresAdapter()
	proposal, err := adapter.Classify(context.Background(), map[string]any{
		"tool": "psql",
		"argv": []string{"-c", "SELECT count(*) FROM users;"},
	})
	if err != nil {
		t.Fatalf("classify: %v", err)
	}
	if proposal.RawRequest["action"] != "select" {
		t.Fatalf("action = %v", proposal.RawRequest["action"])
	}
}

func TestPostgresGoldenCases(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		sql    string
		action string
	}{
		{"drop database", "DROP DATABASE legacy;", "drop"},
		{"truncate only", "TRUNCATE ONLY audit_log;", "truncate"},
		{"delete limited", "DELETE FROM t WHERE id = 1 LIMIT 1;", "delete"},
	}
	adapter := adapters.NewPostgresAdapter()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			proposal, err := adapter.Classify(context.Background(), map[string]any{
				"tool": "psql",
				"argv": []string{"-c", tc.sql},
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

func TestPostgresConnectionURI(t *testing.T) {
	t.Parallel()
	adapter := adapters.NewPostgresAdapter()
	proposal, err := adapter.Classify(context.Background(), map[string]any{
		"tool": "psql",
		"argv": []string{"postgresql://appuser@db.prod.example.com:5432/mydb", "-c", "SELECT 1"},
	})
	if err != nil {
		t.Fatalf("classify: %v", err)
	}
	if proposal.RawRequest["host"] != "db.prod.example.com" {
		t.Fatalf("host = %v", proposal.RawRequest["host"])
	}
	if proposal.RawRequest["database"] != "mydb" {
		t.Fatalf("database = %v", proposal.RawRequest["database"])
	}
}
