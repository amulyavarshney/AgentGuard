package intercept

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/amulyavarshney/agentguard/internal/adapters"
	"github.com/amulyavarshney/agentguard/internal/approval"
	"github.com/amulyavarshney/agentguard/internal/audit"
	"github.com/amulyavarshney/agentguard/internal/config"
	"github.com/amulyavarshney/agentguard/internal/credentials"
	"github.com/amulyavarshney/agentguard/internal/intent"
	"github.com/amulyavarshney/agentguard/internal/model"
	"github.com/amulyavarshney/agentguard/internal/policy"
	"github.com/amulyavarshney/agentguard/internal/session"
)

// GatewayInterceptor wraps agent processes with shim-based interception.
type GatewayInterceptor struct {
	Config     config.Config
	Sessions   *session.Registry
	Engine     policy.Engine
	Broker     *approval.Broker
	Comparator intent.Comparator
}

// NewGatewayInterceptor creates an interceptor wired to config and dependencies.
func NewGatewayInterceptor(cfg config.Config) (*GatewayInterceptor, error) {
	return &GatewayInterceptor{
		Config:     cfg,
		Sessions:   session.NewRegistry(),
		Engine:     policy.NewCompositeEngine(cfg.PolicyDir),
		Broker:     approval.NewBroker(),
		Comparator: intent.NewHeuristicComparator(),
	}, nil
}

// Wrap starts a control channel, materializes shims, and runs the wrapped command.
func (g *GatewayInterceptor) Wrap(ctx context.Context, opts WrapOptions) error {
	if len(opts.Command) == 0 {
		return fmt.Errorf("command is required")
	}

	launcher := strings.Join(opts.Command, " ")
	sess := g.Sessions.Create(opts.Task, opts.Environment, launcher)
	if opts.SessionID != "" {
		sess.ID = opts.SessionID
	}

	store, err := audit.Open(g.Config.AuditDBPath())
	if err != nil {
		return fmt.Errorf("open audit store: %w", err)
	}
	defer store.Close()

	shimDir, cleanupShims, err := materializeShims()
	if err != nil {
		return err
	}
	defer cleanupShims()

	sockPath := filepath.Join(os.TempDir(), fmt.Sprintf("agentguard-%s.sock", sess.ID))
	_ = os.Remove(sockPath)

	gateway := &controlGateway{
		interceptor: g,
		session:     sess,
		store:       store,
		opts:        opts,
		scopeMapper: credentials.NewConfigMapper(g.Config),
		fsAdapter:   adapters.NewFilesystemAdapter(nil),
		shellAdapter: adapters.NewShellAdapter(
			adapters.NewFilesystemAdapter(nil),
		),
		httpAdapter:      adapters.NewHTTPAdapter(),
		postgresAdapter:  adapters.NewPostgresAdapter(),
		awsAdapter:       adapters.NewAWSAdapter(),
	}

	proxyURL, _, err := StartForwardProxy(ctx, sessionMeta{
		id:          sess.ID,
		task:        opts.Task,
		environment: opts.Environment,
	}, gateway.evaluateHTTPRaw)
	if err != nil {
		return fmt.Errorf("start http proxy: %w", err)
	}
	httpProxy, httpsProxy, noProxy := ProxyEnvVars(proxyURL)

	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		return fmt.Errorf("listen control socket: %w", err)
	}
	defer ln.Close()
	defer os.Remove(sockPath)

	serverDone := make(chan error, 1)
	go func() {
		serverDone <- gateway.serve(ctx, ln)
	}()

	realPath := os.Getenv("PATH")
	agentguardBin, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve agentguard binary: %w", err)
	}

	env := os.Environ()
	env = setEnv(env, "AGENTGUARD_SOCK", sockPath)
	env = setEnv(env, "AGENTGUARD_SESSION", sess.ID)
	env = setEnv(env, "AGENTGUARD_TASK", opts.Task)
	env = setEnv(env, "AGENTGUARD_ENV", opts.Environment)
	env = setEnv(env, "AGENTGUARD_BIN", agentguardBin)
	env = setEnv(env, "AGENTGUARD_REAL_PATH", realPath)
	env = setEnv(env, "PATH", shimDir+string(os.PathListSeparator)+realPath)
	env = setEnv(env, "AGENTGUARD_REAL_SHELL", resolveRealShell(opts.Command))
	env = setEnv(env, "HTTP_PROXY", httpProxy)
	env = setEnv(env, "HTTPS_PROXY", httpsProxy)
	env = setEnv(env, "http_proxy", httpProxy)
	env = setEnv(env, "https_proxy", httpsProxy)
	env = setEnv(env, "NO_PROXY", noProxy)
	env = setEnv(env, "no_proxy", noProxy)

	cmd := exec.CommandContext(ctx, opts.Command[0], opts.Command[1:]...)
	cmd.Env = env
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	runErr := cmd.Run()
	exitCode := 0
	if runErr != nil {
		if exitErr, ok := runErr.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else if ctx.Err() != nil {
			exitCode = 130
		} else {
			return runErr
		}
	}

	g.Sessions.End(sess.ID)
	_ = ln.Close()

	select {
	case <-serverDone:
	case <-time.After(2 * time.Second):
	}

	if exitCode != 0 {
		return &ExitError{Code: exitCode}
	}
	return nil
}

// ExitError represents a non-zero wrapped process exit.
type ExitError struct {
	Code int
}

func (e *ExitError) Error() string {
	return fmt.Sprintf("wrapped command exited with code %d", e.Code)
}

type controlGateway struct {
	interceptor     *GatewayInterceptor
	session         session.Session
	store           *audit.Store
	opts            WrapOptions
	scopeMapper     *credentials.ConfigMapper
	fsAdapter       *adapters.FilesystemAdapter
	shellAdapter    *adapters.ShellAdapter
	httpAdapter     *adapters.HTTPAdapter
	postgresAdapter *adapters.PostgresAdapter
	awsAdapter      *adapters.AWSAdapter
	mu              sync.Mutex
}

type proposeRequest struct {
	ID      string   `json:"id"`
	Tool    string   `json:"tool"`
	Argv    []string `json:"argv"`
	CWD     string   `json:"cwd"`
	Task    string   `json:"task,omitempty"`
	Session string   `json:"session_id,omitempty"`
	Env     string   `json:"environment,omitempty"`
}

type proposeResponse struct {
	Decision string `json:"decision"`
	Message  string `json:"message,omitempty"`
	Allowed  bool   `json:"allowed"`
}

func (g *controlGateway) serve(ctx context.Context, ln net.Listener) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				if strings.Contains(err.Error(), "use of closed network connection") {
					return nil
				}
				return err
			}
		}
		go g.handleConn(ctx, conn)
	}
}

func (g *controlGateway) handleConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	decoder := json.NewDecoder(conn)
	encoder := json.NewEncoder(conn)

	for {
		var req proposeRequest
		if err := decoder.Decode(&req); err != nil {
			if err == io.EOF {
				return
			}
			return
		}
		resp := g.handlePropose(ctx, req)
		if err := encoder.Encode(resp); err != nil {
			return
		}
	}
}

func (g *controlGateway) handlePropose(ctx context.Context, req proposeRequest) proposeResponse {
	raw := map[string]any{
		"tool":        req.Tool,
		"argv":        req.Argv,
		"cwd":         req.CWD,
		"session_id":  g.session.ID,
		"environment": g.opts.Environment,
		"task":        g.opts.Task,
	}
	return g.evaluateRaw(ctx, classifyShimTool(req.Tool), raw, g.sessionTask(req))
}

func (g *controlGateway) evaluateHTTPRaw(ctx context.Context, raw map[string]any) (bool, string) {
	resp := g.evaluateRaw(ctx, "http", raw, g.sessionTask(proposeRequest{}))
	return resp.Allowed, resp.Message
}

func (g *controlGateway) evaluateRaw(ctx context.Context, adapterKind string, raw map[string]any, task string) proposeResponse {
	var (
		proposal model.ActionProposal
		err      error
	)
	switch adapterKind {
	case "filesystem":
		proposal, err = g.fsAdapter.Classify(ctx, raw)
	case "shell":
		proposal, err = g.shellAdapter.Classify(ctx, raw)
	case "http":
		proposal, err = g.httpAdapter.Classify(ctx, raw)
	case "postgres":
		proposal, err = g.postgresAdapter.Classify(ctx, raw)
	case "aws":
		proposal, err = g.awsAdapter.Classify(ctx, raw)
	default:
		proposal, err = g.shellAdapter.Classify(ctx, raw)
	}
	if err != nil {
		return proposeResponse{Decision: string(model.PolicyBlock), Message: err.Error(), Allowed: false}
	}

	if proposal.IntentSummary == "" {
		proposal.IntentSummary = task
	}
	if proposal.SessionID == "" {
		proposal.SessionID = g.session.ID
	}
	proposal = g.annotateCredentials(proposal)

	evalResult, err := g.interceptor.Engine.Evaluate(proposal)
	if err != nil {
		evalResult = policy.EvaluationResult{Decision: model.PolicyBlock}
	}
	decision := evalResult.Decision

	intentResult, err := g.interceptor.Comparator.Compare(task, proposal)
	if err != nil {
		intentResult = intent.Result{Aligned: true, Verdict: model.PolicyAllow}
	}
	if !intentResult.Aligned && intentResult.Verdict.Valid() {
		decision = policy.StrictestDecision(decision, intentResult.Verdict)
	}

	result := "blocked"
	allowed := false
	approvers := []string(nil)
	sideEffects := map[string]any{}
	if evalResult.PrimaryRule != "" {
		sideEffects["matched_rule"] = evalResult.PrimaryRule
	}
	if len(evalResult.MatchedRules) > 0 {
		sideEffects["matched_rules"] = evalResult.MatchedRules
	}
	if !intentResult.Aligned {
		sideEffects["intent_aligned"] = false
		sideEffects["intent_verdict"] = string(intentResult.Verdict)
		if len(intentResult.Reasons) > 0 {
			sideEffects["intent_reasons"] = intentResult.Reasons
		}
	} else {
		sideEffects["intent_aligned"] = true
	}

	switch decision {
	case model.PolicyAllow:
		result = "allowed"
		allowed = true
	case model.PolicyBlock, model.PolicyPauseAndEscalate:
		result = "blocked"
	case model.PolicyRequireApproval:
		approvalReq := approval.Request{
			ID:        proposal.ID,
			SessionID: g.session.ID,
			Proposal:  proposal,
			Decision:  decision,
			CreatedAt: time.Now().UTC(),
			Status:    "pending",
		}
		ok, promptErr := g.interceptor.Broker.PromptCLI(ctx, approvalReq, approval.PromptOptions{})
		if promptErr != nil {
			result = "blocked"
		} else if ok {
			result = "approved"
			allowed = true
			approvers = []string{"cli-user"}
		} else {
			result = "denied"
		}
	}

	_, _ = g.store.AppendEvent(ctx, audit.AppendInput{
		Proposal:    proposal,
		Decision:    decision,
		Approvers:   approvers,
		Result:      result,
		SideEffects: sideEffects,
	})

	msg := fmt.Sprintf("action %s: %s", decision, result)
	if !intentResult.Aligned && len(intentResult.Reasons) > 0 {
		msg = fmt.Sprintf("%s (intent: %s)", msg, intentResult.Reasons[0])
	}
	return proposeResponse{
		Decision: string(decision),
		Message:  msg,
		Allowed:  allowed,
	}
}

func (g *controlGateway) annotateCredentials(proposal model.ActionProposal) model.ActionProposal {
	if g.scopeMapper == nil {
		return proposal
	}
	switch proposal.ActionType {
	case "aws":
		profile, _ := proposal.RawRequest["profile"].(string)
		ref, scope, env := g.scopeMapper.ResolveAWS(profile)
		proposal = credentials.AnnotateProposal(proposal, scope, ref)
		if env != "" {
			proposal.Environment = env
		}
	case "postgres":
		host, _ := proposal.RawRequest["host"].(string)
		db, _ := proposal.RawRequest["database"].(string)
		user, _ := proposal.RawRequest["user"].(string)
		ref, scope, env := g.scopeMapper.ResolvePostgres(host, db, user)
		proposal = credentials.AnnotateProposal(proposal, scope, ref)
		if env != "" {
			proposal.Environment = env
		}
	case "http":
		headers := map[string]string{}
		if h, ok := proposal.RawRequest["headers"].(map[string]string); ok {
			headers = h
		} else if h, ok := proposal.RawRequest["headers"].(map[string]any); ok {
			for k, v := range h {
				if s, ok := v.(string); ok {
					headers[k] = s
				}
			}
		}
		ref, scope := g.scopeMapper.ResolveHTTPAuth(headers["authorization"])
		if ref != "" {
			proposal = credentials.AnnotateProposal(proposal, scope, ref)
		}
	}
	return proposal
}

func (g *controlGateway) sessionTask(req proposeRequest) string {
	if task := strings.TrimSpace(g.opts.Task); task != "" {
		return task
	}
	if task := strings.TrimSpace(g.session.Task); task != "" {
		return task
	}
	return strings.TrimSpace(req.Task)
}

func classifyShimTool(tool string) string {
	switch filepath.Base(tool) {
	case "rm", "mv", "chmod", "chown":
		return "filesystem"
	case "sh", "bash":
		return "shell"
	case "psql":
		return "postgres"
	case "aws":
		return "aws"
	default:
		return "shell"
	}
}

func setEnv(env []string, key, value string) []string {
	prefix := key + "="
	out := make([]string, 0, len(env)+1)
	for _, e := range env {
		if strings.HasPrefix(e, prefix) {
			continue
		}
		out = append(out, e)
	}
	return append(out, prefix+value)
}

func resolveRealShell(command []string) string {
	if len(command) == 0 {
		return "/bin/sh"
	}
	base := filepath.Base(command[0])
	if base == "bash" {
		if p, err := exec.LookPath("bash"); err == nil {
			return p
		}
		return "/bin/bash"
	}
	if base == "sh" {
		if p, err := exec.LookPath("sh"); err == nil {
			return p
		}
		return "/bin/sh"
	}
	if p, err := exec.LookPath("sh"); err == nil {
		return p
	}
	return "/bin/sh"
}

// RunShimClient is invoked by shim scripts to propose an action and optionally exec the real binary.
func RunShimClient(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("shim requires a tool name")
	}
	tool := args[0]
	argv := args[1:]
	if len(argv) > 0 && argv[0] == "--" {
		argv = argv[1:]
	}

	sock := os.Getenv("AGENTGUARD_SOCK")
	if sock == "" {
		return fmt.Errorf("AGENTGUARD_SOCK not set")
	}

	cwd, err := os.Getwd()
	if err != nil {
		return err
	}

	req := proposeRequest{
		ID:      fmt.Sprintf("shim-%d", time.Now().UnixNano()),
		Tool:    tool,
		Argv:    argv,
		CWD:     cwd,
		Task:    os.Getenv("AGENTGUARD_TASK"),
		Session: os.Getenv("AGENTGUARD_SESSION"),
		Env:     os.Getenv("AGENTGUARD_ENV"),
	}

	conn, err := net.Dial("unix", sock)
	if err != nil {
		return fmt.Errorf("connect gateway: %w", err)
	}
	defer conn.Close()

	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return fmt.Errorf("send proposal: %w", err)
	}

	var resp proposeResponse
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return fmt.Errorf("read decision: %w", err)
	}

	if !resp.Allowed {
		if resp.Message != "" {
			fmt.Fprintf(os.Stderr, "AgentGuard blocked: %s\n", resp.Message)
		} else {
			fmt.Fprintf(os.Stderr, "AgentGuard blocked: %s (%s)\n", tool, resp.Decision)
		}
		return &ExitError{Code: 1}
	}

	realBin, err := lookupRealBinary(tool)
	if err != nil {
		return err
	}

	realCmd := exec.Command(realBin, argv...)
	realCmd.Stdin = os.Stdin
	realCmd.Stdout = os.Stdout
	realCmd.Stderr = os.Stderr
	realCmd.Env = os.Environ()

	if err := realCmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			if status, ok := exitErr.Sys().(syscall.WaitStatus); ok {
				return &ExitError{Code: status.ExitStatus()}
			}
			return &ExitError{Code: exitErr.ExitCode()}
		}
		return err
	}
	return nil
}

func lookupRealBinary(tool string) (string, error) {
	realPath := os.Getenv("AGENTGUARD_REAL_PATH")
	if realPath == "" {
		realPath = os.Getenv("PATH")
	}
	for _, dir := range filepath.SplitList(realPath) {
		candidate := filepath.Join(dir, tool)
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate, nil
		}
	}
	if p, err := exec.LookPath(tool); err == nil {
		return p, nil
	}
	return "", fmt.Errorf("real binary for %q not found", tool)
}

// materializeShims writes shell wrapper scripts into a temp directory.
func materializeShims() (dir string, cleanup func(), err error) {
	tmp, err := os.MkdirTemp("", "agentguard-shims-*")
	if err != nil {
		return "", nil, err
	}

	bin := os.Getenv("AGENTGUARD_BIN")
	if bin == "" {
		bin, err = os.Executable()
		if err != nil {
			os.RemoveAll(tmp)
			return "", nil, err
		}
	}

	tools := []struct {
		name    string
		forward bool
	}{
		{name: "sh", forward: true},
		{name: "bash", forward: true},
		{name: "rm"},
		{name: "mv"},
		{name: "chmod"},
		{name: "psql"},
		{name: "aws"},
	}

	for _, tool := range tools {
		path := filepath.Join(tmp, tool.name)
		var content string
		if tool.forward {
			content = fmt.Sprintf(`#!/bin/sh
set -eu
REAL="${AGENTGUARD_REAL_SHELL:-/bin/sh}"
if [ "$(basename "$0")" = "bash" ]; then
  REAL="${AGENTGUARD_REAL_SHELL:-/bin/bash}"
fi
exec "$REAL" "$@"
`)
		} else {
			content = fmt.Sprintf(`#!/bin/sh
set -eu
exec %q __shim__ %q -- "$@"
`, bin, tool.name)
		}
		if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
			os.RemoveAll(tmp)
			return "", nil, err
		}
	}

	return tmp, func() { _ = os.RemoveAll(tmp) }, nil
}

// DecodeProposeRequest is exported for tests.
func DecodeProposeRequest(r io.Reader) (proposeRequest, error) {
	var req proposeRequest
	err := json.NewDecoder(r).Decode(&req)
	return req, err
}

// EncodeProposeResponse is exported for tests.
func EncodeProposeResponse(w io.Writer, resp proposeResponse) error {
	return json.NewEncoder(w).Encode(resp)
}

// ReadLine is a test helper.
func ReadLine(r io.Reader) (string, error) {
	return bufio.NewReader(r).ReadString('\n')
}
