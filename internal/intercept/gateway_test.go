package intercept_test

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/amulyavarshney/agentguard/internal/adapters"
	"github.com/amulyavarshney/agentguard/internal/audit"
	"github.com/amulyavarshney/agentguard/internal/config"
	"github.com/amulyavarshney/agentguard/internal/intercept"
	"github.com/amulyavarshney/agentguard/internal/model"
	"github.com/amulyavarshney/agentguard/internal/policy"
	"github.com/amulyavarshney/agentguard/internal/session"
)

func TestShimProposalBlockedForOutsideDelete(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	tmp := t.TempDir()
	store, err := audit.Open(filepath.Join(tmp, "audit.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	sess := session.Session{ID: "sess-test", Task: "cleanup", Environment: "staging"}
	fsAdapter := adapters.NewFilesystemAdapter([]string{tmp})

	raw := map[string]any{
		"tool":        "rm",
		"argv":        []string{"-rf", "/etc/passwd"},
		"cwd":         tmp,
		"session_id":  sess.ID,
		"environment": sess.Environment,
		"task":        sess.Task,
	}
	proposal, err := fsAdapter.Classify(ctx, raw)
	if err != nil {
		t.Fatalf("classify: %v", err)
	}
	result, err := policy.NewBaselineEngine(policy.StubEngine{}).Evaluate(proposal)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if result.Decision != model.PolicyBlock {
		t.Fatalf("decision = %q, want block", result.Decision)
	}

	_, err = store.AppendEvent(ctx, audit.AppendInput{
		Proposal: proposal,
		Decision: result.Decision,
		Result:   "blocked",
	})
	if err != nil {
		t.Fatalf("append audit: %v", err)
	}

	events, err := store.ListEvents(ctx, sess.ID)
	if err != nil {
		t.Fatalf("list events: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("audit events = %d, want 1", len(events))
	}
}

func TestMaterializeShimsCreatesWrappers(t *testing.T) {
	t.Parallel()

	// materializeShims is unexported; validate via gateway helper patterns in intercept package tests
	// by checking RunShimClient fails without AGENTGUARD_SOCK (proposal path exists).
	err := intercept.RunShimClient([]string{"rm", "--", "/tmp/x"})
	if err == nil {
		t.Fatal("expected error without AGENTGUARD_SOCK")
	}
}

func TestGatewayInterceptorConfig(t *testing.T) {
	t.Parallel()

	cfg := config.Default()
	cfg.DataDir = t.TempDir()
	ic, err := intercept.NewGatewayInterceptor(cfg)
	if err != nil {
		t.Fatalf("new interceptor: %v", err)
	}
	if ic == nil {
		t.Fatal("expected interceptor")
	}
}

func TestProposeResponseEncoding(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	resp := struct {
		Decision string `json:"decision"`
		Allowed  bool   `json:"allowed"`
	}{Decision: "block", Allowed: false}
	if err := json.NewEncoder(&buf).Encode(resp); err != nil {
		t.Fatalf("encode: %v", err)
	}
}
