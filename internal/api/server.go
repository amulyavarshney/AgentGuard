package api

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/amulyavarshney/agentguard/internal/approval"
	"github.com/amulyavarshney/agentguard/internal/audit"
	"github.com/amulyavarshney/agentguard/internal/intent"
	"github.com/amulyavarshney/agentguard/internal/model"
	"github.com/amulyavarshney/agentguard/internal/policy"
	"github.com/amulyavarshney/agentguard/internal/session"
)

//go:embed static/*
var embeddedStatic embed.FS

// Server exposes the local AgentGuard control-plane API.
type Server struct {
	listen   string
	sessions *session.Registry
	audit    *audit.Store
	approvals *approval.Broker
	policies *policy.Registry
	policyDir string
	http     *http.Server
	staticFS http.FileSystem
}

// Options configures the API server.
type Options struct {
	Listen    string
	PolicyDir string
}

// NewServer constructs an API server bound to listen address.
func NewServer(opts Options, sessions *session.Registry, auditStore *audit.Store, approvals *approval.Broker, policies *policy.Registry) *Server {
	s := &Server{
		listen:    opts.Listen,
		sessions:  sessions,
		audit:     auditStore,
		approvals: approvals,
		policies:  policies,
		policyDir: opts.PolicyDir,
		staticFS:  resolveStaticFS(),
	}
	mux := http.NewServeMux()

	// Health + API
	mux.HandleFunc("GET /health", s.handleHealth)
	mux.HandleFunc("GET /api/v1/sessions", s.handleListSessions)
	mux.HandleFunc("GET /api/v1/sessions/{id}", s.handleGetSession)
	mux.HandleFunc("GET /api/v1/sessions/{id}/events", s.handleListSessionEvents)
	mux.HandleFunc("GET /api/v1/sessions/{id}/verify", s.handleVerifySessionChain)
	mux.HandleFunc("GET /api/v1/events", s.handleListEvents)
	mux.HandleFunc("POST /api/v1/events/{id}/save-as-rule", s.handleSaveEventAsRule)
	mux.HandleFunc("GET /api/v1/approvals", s.handleListApprovals)
	mux.HandleFunc("POST /api/v1/approvals/{id}/approve", s.handleApprove)
	mux.HandleFunc("POST /api/v1/approvals/{id}/deny", s.handleDeny)
	mux.HandleFunc("POST /api/v1/approvals/{id}/save-as-rule", s.handleSaveAsRule)
	mux.HandleFunc("POST /api/v1/policies/evaluate", s.handleEvaluatePolicy)
	mux.HandleFunc("POST /api/v1/policies/learned", s.handleSaveLearnedPolicy)
	mux.HandleFunc("GET /api/v1/policies", s.handleListPolicies)
	mux.HandleFunc("PATCH /api/v1/policies/{id}", s.handlePatchPolicy)
	mux.HandleFunc("GET /api/v1/policies/{id}/rules", s.handleGetPolicyRules)
	mux.HandleFunc("GET /api/v1/risk/summary", s.handleRiskSummary)
	mux.HandleFunc("GET /api/v1/credentials/scopes", s.handleCredentialScopes)

	// Static UI (SPA fallback)
	mux.HandleFunc("GET /{$}", s.serveIndex)
	mux.Handle("GET /assets/", s.staticHandler())
	mux.HandleFunc("GET /{path...}", s.serveSPA)

	s.http = &http.Server{
		Addr:              opts.Listen,
		Handler:           withCORS(mux),
		ReadHeaderTimeout: 5 * time.Second,
	}
	return s
}

func resolveStaticFS() http.FileSystem {
	// Prefer built web/dist on disk (dev or post-npm-build go build).
	candidates := []string{
		"web/dist",
		filepath.Join("..", "web", "dist"),
	}
	for _, dir := range candidates {
		if info, err := os.Stat(filepath.Join(dir, "index.html")); err == nil && !info.IsDir() {
			return http.Dir(dir)
		}
	}
	sub, err := fs.Sub(embeddedStatic, "static")
	if err != nil {
		return http.FS(embeddedStatic)
	}
	return http.FS(sub)
}

func (s *Server) staticHandler() http.Handler {
	return http.FileServer(s.staticFS)
}

func (s *Server) serveIndex(w http.ResponseWriter, r *http.Request) {
	s.serveFile(w, "index.html")
}

func (s *Server) serveSPA(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/")
	if path == "" {
		s.serveIndex(w, r)
		return
	}
	if f, err := s.staticFS.Open(path); err == nil {
		_ = f.Close()
		http.FileServer(s.staticFS).ServeHTTP(w, r)
		return
	}
	s.serveIndex(w, r)
}

func (s *Server) serveFile(w http.ResponseWriter, name string) {
	f, err := s.staticFS.Open(name)
	if err != nil {
		http.Error(w, "console not built — run `cd web && npm install && npm run build` or use `npm run dev` with proxy", http.StatusNotFound)
		return
	}
	defer f.Close()
	stat, err := f.Stat()
	if err != nil {
		http.Error(w, "stat file", http.StatusInternalServerError)
		return
	}
	if stat.IsDir() {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	content, err := io.ReadAll(f)
	if err != nil {
		http.Error(w, "read file", http.StatusInternalServerError)
		return
	}
	if strings.HasSuffix(name, ".html") {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(content)
}

// Handler returns the HTTP handler for testing and embedding.
func (s *Server) Handler() http.Handler {
	return s.http.Handler
}

// ListenAndServe starts the HTTP server.
func (s *Server) ListenAndServe() error {
	return s.http.ListenAndServe()
}

// Shutdown gracefully stops the server.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.http.Shutdown(ctx)
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleListSessions(w http.ResponseWriter, r *http.Request) {
	sessions := s.mergeSessions(r.Context())
	writeJSON(w, http.StatusOK, sessions)
}

func (s *Server) mergeSessions(ctx context.Context) []session.Session {
	seen := map[string]session.Session{}
	for _, sess := range s.sessions.List() {
		seen[sess.ID] = sess
	}
	if s.audit != nil {
		derived, err := s.audit.DeriveSessions(ctx)
		if err == nil {
			for _, sess := range derived {
				if existing, ok := seen[sess.ID]; ok {
					if existing.Task == "" {
						existing.Task = sess.Task
					}
					if existing.Environment == "" {
						existing.Environment = sess.Environment
					}
					if existing.Status == session.StatusEnded && sess.EndedAt != nil {
						existing.EndedAt = sess.EndedAt
					}
					seen[sess.ID] = existing
					continue
				}
				seen[sess.ID] = sess
			}
		}
	}
	out := make([]session.Session, 0, len(seen))
	for _, sess := range seen {
		out = append(out, sess)
	}
	if out == nil {
		out = []session.Session{}
	}
	return out
}

func (s *Server) handleGetSession(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if sess, ok := s.sessions.Get(id); ok {
		writeJSON(w, http.StatusOK, sess)
		return
	}
	for _, sess := range s.mergeSessions(r.Context()) {
		if sess.ID == id {
			writeJSON(w, http.StatusOK, sess)
			return
		}
	}
	writeError(w, http.StatusNotFound, fmt.Errorf("session %q not found", id))
}

func (s *Server) handleVerifySessionChain(w http.ResponseWriter, r *http.Request) {
	sessionID := r.PathValue("id")
	if s.audit == nil {
		writeError(w, http.StatusServiceUnavailable, fmt.Errorf("audit store not configured"))
		return
	}
	if err := s.audit.VerifySessionChain(r.Context(), sessionID); err != nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"session_id": sessionID,
			"valid":      false,
			"error":      err.Error(),
		})
		return
	}
	events, err := s.audit.ListEvents(r.Context(), sessionID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"session_id":  sessionID,
		"valid":       true,
		"event_count": len(events),
		"head_hash":   chainHeadHash(events),
	})
}

func chainHeadHash(events []model.AuditEvent) string {
	if len(events) == 0 {
		return ""
	}
	return events[len(events)-1].EventHash
}

func (s *Server) handleSaveEventAsRule(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if s.audit == nil {
		writeError(w, http.StatusServiceUnavailable, fmt.Errorf("audit store not configured"))
		return
	}
	ev, err := s.audit.GetEvent(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}

	var body saveAsRuleBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil && err.Error() != "EOF" {
		writeError(w, http.StatusBadRequest, fmt.Errorf("decode body: %w", err))
		return
	}

	scope := body.Scope
	if scope == "" {
		scope = "org"
	}
	decision := model.PolicyBlock
	if body.Decision == string(model.PolicyRequireApproval) {
		decision = model.PolicyRequireApproval
	} else if ev.Decision == model.PolicyRequireApproval {
		decision = model.PolicyRequireApproval
	}

	path, err := policy.SaveLearnedRule(s.policyDir, policy.SaveRuleInput{
		Proposal:  ev.Proposal,
		Scope:     scope,
		ScopeID:   body.ScopeID,
		Decision:  decision,
		Reason:    body.Reason,
		SessionID: ev.SessionID,
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	if s.policies != nil {
		_, _ = s.policies.List()
	}

	writeJSON(w, http.StatusCreated, map[string]any{
		"status":    "saved",
		"file_path": path,
		"scope":     scope,
		"scope_id":  body.ScopeID,
		"event_id":  id,
	})
}

func (s *Server) handleListSessionEvents(w http.ResponseWriter, r *http.Request) {
	sessionID := r.PathValue("id")
	events, err := s.audit.ListEvents(r.Context(), sessionID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if events == nil {
		events = []model.AuditEvent{}
	}
	writeJSON(w, http.StatusOK, events)
}

func (s *Server) handleListEvents(w http.ResponseWriter, r *http.Request) {
	decision := r.URL.Query().Get("decision")
	limit := queryLimit(r, 100)

	var (
		events []model.AuditEvent
		err    error
	)
	if decision != "" {
		events, err = s.audit.ListEventsByDecision(r.Context(), model.PolicyDecision(decision), limit)
	} else {
		events, err = s.audit.ListAllEvents(r.Context(), limit)
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if events == nil {
		events = []model.AuditEvent{}
	}
	writeJSON(w, http.StatusOK, events)
}

func (s *Server) handleListApprovals(w http.ResponseWriter, _ *http.Request) {
	pending := s.approvals.ListPending()
	if pending == nil {
		pending = []approval.Request{}
	}
	writeJSON(w, http.StatusOK, pending)
}

func (s *Server) handleApprove(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	req, ok := s.approvals.Approve(id)
	if !ok {
		writeError(w, http.StatusNotFound, fmt.Errorf("approval %q not found", id))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":  "approved",
		"request": req,
	})
}

func (s *Server) handleDeny(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	req, ok := s.approvals.Deny(id)
	if !ok {
		writeError(w, http.StatusNotFound, fmt.Errorf("approval %q not found", id))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":  "denied",
		"request": req,
	})
}

type saveAsRuleBody struct {
	Scope   string `json:"scope"`
	ScopeID string `json:"scope_id"`
	Reason  string `json:"reason,omitempty"`
	Decision string `json:"decision,omitempty"`
}

func (s *Server) handleSaveAsRule(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	req, ok := s.approvals.Get(id)
	if !ok {
		writeError(w, http.StatusNotFound, fmt.Errorf("approval %q not found", id))
		return
	}

	var body saveAsRuleBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil && err.Error() != "EOF" {
		writeError(w, http.StatusBadRequest, fmt.Errorf("decode body: %w", err))
		return
	}

	scope := body.Scope
	if scope == "" {
		scope = "org"
	}
	decision := model.PolicyBlock
	if body.Decision == string(model.PolicyRequireApproval) {
		decision = model.PolicyRequireApproval
	}

	path, err := policy.SaveLearnedRule(s.policyDir, policy.SaveRuleInput{
		Proposal:  req.Proposal,
		Scope:     scope,
		ScopeID:   body.ScopeID,
		Decision:  decision,
		Reason:    body.Reason,
		SessionID: req.SessionID,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	_, _ = s.approvals.Deny(id)

	writeJSON(w, http.StatusCreated, map[string]any{
		"status":    "saved",
		"file_path": path,
		"scope":     scope,
		"scope_id":  body.ScopeID,
	})
}

func (s *Server) handleEvaluatePolicy(w http.ResponseWriter, r *http.Request) {
	var proposal model.ActionProposal
	if err := json.NewDecoder(r.Body).Decode(&proposal); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("decode proposal: %w", err))
		return
	}
	var engine policy.Engine
	if s.policies != nil {
		engine = s.policies.Engine()
	} else {
		eng, err := policy.NewEngineFromDir(s.policyDir)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		engine = eng
	}
	result, err := engine.Evaluate(proposal)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	task := strings.TrimSpace(proposal.IntentSummary)
	intentResult, err := intent.NewHeuristicComparator().Compare(task, proposal)
	if err == nil && !intentResult.Aligned && intentResult.Verdict.Valid() {
		result.Decision = policy.StrictestDecision(result.Decision, intentResult.Verdict)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"decision":       result.Decision,
		"matched_rules":  result.MatchedRules,
		"primary_rule":   result.PrimaryRule,
		"require":        result.Require,
		"intent_aligned": intentResult.Aligned,
		"intent_verdict": intentResult.Verdict,
		"intent_reasons": intentResult.Reasons,
	})
}

func (s *Server) handleSaveLearnedPolicy(w http.ResponseWriter, r *http.Request) {
	var input policy.SaveRuleInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("decode body: %w", err))
		return
	}
	path, err := policy.SaveLearnedRule(s.policyDir, input)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"status":    "saved",
		"file_path": path,
		"scope":     input.Scope,
		"scope_id":  input.ScopeID,
	})
}

func (s *Server) handleListPolicies(w http.ResponseWriter, _ *http.Request) {
	if s.policies == nil {
		writeJSON(w, http.StatusOK, []policy.PolicyEntry{})
		return
	}
	entries, err := s.policies.List()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, entries)
}

type patchPolicyBody struct {
	Enabled *bool `json:"enabled"`
}

func (s *Server) handlePatchPolicy(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if s.policies == nil {
		writeError(w, http.StatusServiceUnavailable, fmt.Errorf("policy registry not configured"))
		return
	}
	var body patchPolicyBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if body.Enabled == nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("enabled field required"))
		return
	}
	if err := s.policies.SetEnabled(id, *body.Enabled); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "enabled": *body.Enabled})
}

func (s *Server) handleGetPolicyRules(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if s.policies == nil {
		writeError(w, http.StatusServiceUnavailable, fmt.Errorf("policy registry not configured"))
		return
	}
	entries, err := s.policies.List()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	var filePath string
	for _, e := range entries {
		if e.ID == id {
			filePath = e.FilePath
			break
		}
	}
	if filePath == "" {
		writeError(w, http.StatusNotFound, fmt.Errorf("policy %q not found", id))
		return
	}
	doc, err := policy.LoadDocument(filePath)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, doc)
}

type riskBucket struct {
	Key   string `json:"key"`
	Count int    `json:"count"`
}

type riskSummary struct {
	ByAgent []riskBucket `json:"by_agent"`
	ByRepo  []riskBucket `json:"by_repo"`
	ByRule  []riskBucket `json:"by_rule"`
	ByDecision []riskBucket `json:"by_decision"`
	TotalEvents int       `json:"total_events"`
}

func (s *Server) handleRiskSummary(w http.ResponseWriter, r *http.Request) {
	events, err := s.audit.ListAllEvents(r.Context(), 500)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	agentCounts := map[string]int{}
	repoCounts := map[string]int{}
	ruleCounts := map[string]int{}
	decisionCounts := map[string]int{}

	sessions := map[string]session.Session{}
	for _, sess := range s.sessions.List() {
		sessions[sess.ID] = sess
	}

	for _, ev := range events {
		decisionCounts[string(ev.Decision)]++

		agent := "unknown"
		if sess, ok := sessions[ev.SessionID]; ok && sess.AgentLauncher != "" {
			agent = sess.AgentLauncher
		} else if ev.Proposal.ModelContext.Model != "" {
			agent = ev.Proposal.ModelContext.Model
		}
		agentCounts[agent]++

		repo := ev.Proposal.Environment
		if repo == "" {
			repo = "local"
		}
		if rule, ok := ev.SideEffects["matched_rule"].(string); ok && rule != "" {
			ruleCounts[rule]++
		} else if ev.Decision != model.PolicyAllow {
			ruleCounts[string(ev.Decision)]++
		}
		repoCounts[repo]++
	}

	writeJSON(w, http.StatusOK, riskSummary{
		ByAgent:     toBuckets(agentCounts),
		ByRepo:      toBuckets(repoCounts),
		ByRule:      toBuckets(ruleCounts),
		ByDecision:  toBuckets(decisionCounts),
		TotalEvents: len(events),
	})
}

type credentialScopeEntry struct {
	Ref    string   `json:"ref"`
	Scope  []string `json:"scope"`
	LastUsed string `json:"last_used"`
	UsageCount int  `json:"usage_count"`
}

func (s *Server) handleCredentialScopes(w http.ResponseWriter, r *http.Request) {
	events, err := s.audit.ListAllEvents(r.Context(), 200)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	byRef := map[string]*credentialScopeEntry{}
	for _, ev := range events {
		ref := ev.Proposal.CredentialRef
		if ref == "" {
			continue
		}
		entry, ok := byRef[ref]
		if !ok {
			entry = &credentialScopeEntry{
				Ref:   ref,
				Scope: ev.Proposal.CredentialScope,
			}
			byRef[ref] = entry
		}
		entry.UsageCount++
		entry.LastUsed = ev.Timestamp.Format(time.RFC3339)
		if len(ev.Proposal.CredentialScope) > len(entry.Scope) {
			entry.Scope = ev.Proposal.CredentialScope
		}
	}

	out := make([]credentialScopeEntry, 0, len(byRef))
	for _, e := range byRef {
		out = append(out, *e)
	}
	if out == nil {
		out = []credentialScopeEntry{}
	}
	writeJSON(w, http.StatusOK, out)
}

func toBuckets(m map[string]int) []riskBucket {
	out := make([]riskBucket, 0, len(m))
	for k, v := range m {
		out = append(out, riskBucket{Key: k, Count: v})
	}
	return out
}

func queryLimit(r *http.Request, defaultLimit int) int {
	raw := r.URL.Query().Get("limit")
	if raw == "" {
		return defaultLimit
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n <= 0 {
		return defaultLimit
	}
	if n > 500 {
		return 500
	}
	return n
}

func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PATCH, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]string{"error": err.Error()})
}

// Addr returns the configured listen address.
func (s *Server) Addr() string {
	return s.listen
}

// String returns a human-readable description.
func (s *Server) String() string {
	return fmt.Sprintf("agentguard api on %s", s.listen)
}
