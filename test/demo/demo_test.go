package demo_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/amulyavarshney/agentguard/internal/adapters"
	"github.com/amulyavarshney/agentguard/internal/api"
	"github.com/amulyavarshney/agentguard/internal/approval"
	"github.com/amulyavarshney/agentguard/internal/audit"
	"github.com/amulyavarshney/agentguard/internal/config"
	"github.com/amulyavarshney/agentguard/internal/intent"
	"github.com/amulyavarshney/agentguard/internal/model"
	"github.com/amulyavarshney/agentguard/internal/policy"
	"github.com/amulyavarshney/agentguard/internal/session"
)

const demoTask = "fix auth error in staging"

func TestDemoPathBlocksDestructiveAWSAction(t *testing.T) {
	root := demoWorkspace(t)
	bin := buildAgentGuard(t, root)

	runDemoExec(t, bin, root, demoTask)

	store := openAudit(t, filepath.Join(root, ".agentguard", "audit.db"))
	defer store.Close()

	ctx := context.Background()
	sessions, err := store.DeriveSessions(ctx)
	if err != nil {
		t.Fatalf("derive sessions: %v", err)
	}
	if len(sessions) == 0 {
		t.Fatal("expected at least one session in audit log")
	}
	sessionID := sessions[0].ID

	events, err := store.ListEvents(ctx, sessionID)
	if err != nil {
		t.Fatalf("list events: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("events = %d, want 1", len(events))
	}
	ev := events[0]
	if ev.Decision != model.PolicyBlock {
		t.Fatalf("decision = %q, want block", ev.Decision)
	}
	if ev.Result != "blocked" {
		t.Fatalf("result = %q, want blocked", ev.Result)
	}
	if !strings.Contains(ev.Proposal.Command, "delete-db-instance") {
		t.Fatalf("unexpected command: %q", ev.Proposal.Command)
	}
	if err := store.VerifySessionChain(ctx, sessionID); err != nil {
		t.Fatalf("verify chain: %v", err)
	}
}

func TestDemoPathSaveAsRuleBlocksFutureIdenticalClass(t *testing.T) {
	root := demoWorkspace(t)
	bin := buildAgentGuard(t, root)

	runDemoExec(t, bin, root, demoTask)

	store := openAudit(t, filepath.Join(root, ".agentguard", "audit.db"))
	defer store.Close()

	ctx := context.Background()
	sessions, err := store.DeriveSessions(ctx)
	if err != nil {
		t.Fatalf("derive sessions: %v", err)
	}
	events, err := store.ListEvents(ctx, sessions[0].ID)
	if err != nil {
		t.Fatalf("list events: %v", err)
	}
	ev := events[0]

	policyDir := filepath.Join(root, "policies")
	path, err := policy.SaveLearnedRule(policyDir, policy.SaveRuleInput{
		Proposal:  ev.Proposal,
		Scope:     "org",
		Decision:  model.PolicyBlock,
		Reason:    "human denied prod RDS delete during staging task",
		SessionID: ev.SessionID,
	})
	if err != nil {
		t.Fatalf("save learned rule: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("learned rule file: %v", err)
	}

	engine, err := policy.NewEngineFromDir(policyDir)
	if err != nil {
		t.Fatalf("reload engine: %v", err)
	}
	proposal, err := adapters.NewAWSAdapter().Classify(ctx, map[string]any{
		"tool":        "aws",
		"argv":        []string{"rds", "delete-db-instance", "--db-instance-identifier", "prod-db"},
		"environment": "production",
		"session_id":  "sess-repeat",
		"task":        "decommission prod-db",
	})
	if err != nil {
		t.Fatalf("classify: %v", err)
	}
	result, err := engine.Evaluate(proposal)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if result.Decision != model.PolicyBlock {
		t.Fatalf("after learned rule policy decision = %q, want block", result.Decision)
	}
}

func TestDemoPathAPIReplayAndSaveAsRule(t *testing.T) {
	root := demoWorkspace(t)
	bin := buildAgentGuard(t, root)

	runDemoExec(t, bin, root, demoTask)

	cfg := config.Config{
		DataDir:   filepath.Join(root, ".agentguard"),
		PolicyDir: filepath.Join(root, "policies"),
		API:       config.APIConfig{Listen: "127.0.0.1:0"},
	}
	store := openAudit(t, cfg.AuditDBPath())
	defer store.Close()

	reg, err := policy.NewRegistry(cfg.PolicyDir, cfg.DataDir)
	if err != nil {
		t.Fatalf("policy registry: %v", err)
	}
	srv := api.NewServer(api.Options{
		Listen:    cfg.API.Listen,
		PolicyDir: cfg.PolicyDir,
	}, session.NewRegistry(), store, approval.NewBroker(), reg)

	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	ctx := context.Background()
	sessions, err := store.DeriveSessions(ctx)
	if err != nil {
		t.Fatalf("derive sessions: %v", err)
	}
	sessionID := sessions[0].ID

	resp, err := http.Get(ts.URL + "/api/v1/sessions/" + sessionID + "/verify")
	if err != nil {
		t.Fatalf("verify request: %v", err)
	}
	defer resp.Body.Close()
	var verify map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&verify); err != nil {
		t.Fatalf("decode verify: %v", err)
	}
	if verify["valid"] != true {
		t.Fatalf("verify response = %+v, want valid=true", verify)
	}

	events, err := store.ListEvents(ctx, sessionID)
	if err != nil {
		t.Fatalf("list events: %v", err)
	}
	body, _ := json.Marshal(map[string]string{"scope": "org", "reason": "demo deny"})
	saveResp, err := http.Post(ts.URL+"/api/v1/events/"+events[0].ID+"/save-as-rule", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("save-as-rule: %v", err)
	}
	defer saveResp.Body.Close()
	if saveResp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(saveResp.Body)
		t.Fatalf("save-as-rule status = %d body = %s", saveResp.StatusCode, b)
	}
}

func TestDemoPathIntentBlocksStagingTaskAgainstProdResource(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	proposal, err := adapters.NewAWSAdapter().Classify(ctx, map[string]any{
		"tool":        "aws",
		"argv":        []string{"rds", "delete-db-instance", "--db-instance-identifier", "prod-db"},
		"environment": "staging",
		"session_id":  "sess-intent",
		"task":        demoTask,
	})
	if err != nil {
		t.Fatalf("classify: %v", err)
	}
	result, err := intent.NewHeuristicComparator().Compare(demoTask, proposal)
	if err != nil {
		t.Fatalf("compare: %v", err)
	}
	if result.Aligned {
		t.Fatal("expected intent mismatch for staging fix task vs prod-db delete")
	}
	if result.Verdict != model.PolicyBlock {
		t.Fatalf("intent verdict = %q, want block", result.Verdict)
	}
}

func demoWorkspace(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	policyRoot := filepath.Join(root, "policies")
	if err := os.MkdirAll(filepath.Join(policyRoot, "default"), 0o755); err != nil {
		t.Fatalf("mkdir policies: %v", err)
	}
	src := filepath.Join("..", "..", "policies", "default", "destructive-pack.yaml")
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("read default pack: %v", err)
	}
	if err := os.WriteFile(filepath.Join(policyRoot, "default", "destructive-pack.yaml"), data, 0o644); err != nil {
		t.Fatalf("write default pack: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(root, ".agentguard"), 0o755); err != nil {
		t.Fatalf("mkdir data: %v", err)
	}
	cfg := config.Default()
	cfg.DataDir = filepath.Join(root, ".agentguard")
	cfg.PolicyDir = policyRoot
	cfgYAML := fmt.Sprintf("data_dir: %s\npolicy_dir: %s\n", cfg.DataDir, cfg.PolicyDir)
	if err := os.WriteFile(filepath.Join(root, "agentguard.yaml"), []byte(cfgYAML), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return root
}

func buildAgentGuard(t *testing.T, root string) string {
	t.Helper()
	bin := filepath.Join(root, "agentguard")
	cmd := exec.Command("go", "build", "-o", bin, "./cmd/agentguard")
	cmd.Dir = filepath.Join("..", "..")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("build agentguard: %v\n%s", err, out)
	}
	return bin
}

func runDemoExec(t *testing.T, bin, root, task string) {
	t.Helper()
	cmd := exec.Command(bin, "exec", "--task", task, "--", "bash", "-c",
		"aws rds delete-db-instance --db-instance-identifier prod-db")
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "AGENTGUARD_AUTO_DENY=1")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected exec to fail (blocked), output:\n%s", out)
	}
	if !strings.Contains(string(out), "blocked") && !strings.Contains(string(out), "AgentGuard") {
		t.Fatalf("expected block message, got:\n%s", out)
	}
}

func openAudit(t *testing.T, path string) *audit.Store {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		store, err := audit.Open(path)
		if err == nil {
			return store
		}
		if time.Now().After(deadline) {
			t.Fatalf("open audit store: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
