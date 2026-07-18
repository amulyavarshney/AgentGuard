package adapters_test

import (
	"context"
	"testing"

	"github.com/amulyavarshney/agentguard/internal/adapters"
	"github.com/amulyavarshney/agentguard/internal/model"
	"github.com/amulyavarshney/agentguard/internal/policy"
)

func TestHTTPAdapterLargeEgress(t *testing.T) {
	t.Parallel()
	adapter := adapters.NewHTTPAdapter()
	proposal, err := adapter.Classify(context.Background(), map[string]any{
		"method":       "POST",
		"host":         "api.example.com",
		"path":         "/upload",
		"scheme":       "http",
		"egress_bytes": int64(20 * 1024 * 1024),
		"session_id":   "sess-http",
		"environment":  "staging",
	})
	if err != nil {
		t.Fatalf("classify: %v", err)
	}
	if proposal.ActionType != "http" {
		t.Fatalf("action_type = %q", proposal.ActionType)
	}
	if proposal.RawRequest["egress_bytes"] != int64(20*1024*1024) {
		t.Fatalf("egress_bytes = %v", proposal.RawRequest["egress_bytes"])
	}
	if proposal.RawRequest["large_egress"] != true {
		t.Fatalf("large_egress = %v", proposal.RawRequest["large_egress"])
	}

	engine := loadDefaultEngine(t)
	result, err := engine.Evaluate(proposal)
	if err != nil {
		t.Fatal(err)
	}
	if result.Decision != model.PolicyPauseAndEscalate {
		t.Fatalf("decision = %q, want pause_and_escalate", result.Decision)
	}
}

func TestHTTPAdapterSecretsPath(t *testing.T) {
	t.Parallel()
	adapter := adapters.NewHTTPAdapter()
	proposal, err := adapter.Classify(context.Background(), map[string]any{
		"method": "GET",
		"host":   "secrets.example.com",
		"path":   "/v1/secrets/prod-db",
		"scheme": "https",
	})
	if err != nil {
		t.Fatalf("classify: %v", err)
	}
	if proposal.RawRequest["action"] != "secrets_get" {
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

func TestHTTPAdapterCONNECT(t *testing.T) {
	t.Parallel()
	adapter := adapters.NewHTTPAdapter()
	proposal, err := adapter.Classify(context.Background(), map[string]any{
		"method":  "CONNECT",
		"host":    "api.stripe.com:443",
		"connect": true,
		"scheme":  "https",
	})
	if err != nil {
		t.Fatalf("classify: %v", err)
	}
	if proposal.RawRequest["action"] != "https_tunnel" {
		t.Fatalf("action = %v", proposal.RawRequest["action"])
	}
	if proposal.Command != "CONNECT api.stripe.com:443" {
		t.Fatalf("command = %q", proposal.Command)
	}
}

func loadDefaultEngine(t *testing.T) *policy.DefaultEngine {
	t.Helper()
	engine, err := policy.NewEngineFromDefaultDir("../../policies")
	if err != nil {
		t.Fatalf("NewEngineFromDefaultDir: %v", err)
	}
	return engine
}
