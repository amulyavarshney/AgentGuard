package approval

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/amulyavarshney/agentguard/internal/model"
)

// Request represents a pending human approval for a gated action.
type Request struct {
	ID        string               `json:"id"`
	SessionID string               `json:"session_id"`
	Proposal  model.ActionProposal `json:"proposal"`
	Decision  model.PolicyDecision `json:"decision"`
	CreatedAt time.Time            `json:"created_at"`
	Status    string               `json:"status"`
}

// Broker manages the local approval queue (CLI/UI integration deferred).
type Broker struct {
	mu       sync.RWMutex
	pending  map[string]Request
	waiters  map[string]chan bool
}

// NewBroker creates an empty approval broker.
func NewBroker() *Broker {
	return &Broker{
		pending: make(map[string]Request),
		waiters: make(map[string]chan bool),
	}
}

// Enqueue adds a request to the pending queue.
func (b *Broker) Enqueue(req Request) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.pending[req.ID] = req
}

// ListPending returns all pending approval requests.
func (b *Broker) ListPending() []Request {
	b.mu.RLock()
	defer b.mu.RUnlock()
	results := make([]Request, 0, len(b.pending))
	for _, req := range b.pending {
		results = append(results, req)
	}
	return results
}

// Approve marks a request as approved and removes it from the queue.
func (b *Broker) Approve(id string) (Request, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	req, ok := b.pending[id]
	if !ok {
		return Request{}, false
	}
	req.Status = "approved"
	delete(b.pending, id)
	if ch, ok := b.waiters[id]; ok {
		delete(b.waiters, id)
		select {
		case ch <- true:
		default:
		}
		close(ch)
	}
	return req, true
}

// Deny marks a request as denied and removes it from the queue.
func (b *Broker) Deny(id string) (Request, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	req, ok := b.pending[id]
	if !ok {
		return Request{}, false
	}
	req.Status = "denied"
	delete(b.pending, id)
	if ch, ok := b.waiters[id]; ok {
		delete(b.waiters, id)
		select {
		case ch <- false:
		default:
		}
		close(ch)
	}
	return req, true
}

// PromptOptions configures interactive CLI approval.
type PromptOptions struct {
	Timeout time.Duration
	Reader  io.Reader
	Writer  io.Writer
}

// Get returns a pending approval request by ID without modifying it.
func (b *Broker) Get(id string) (Request, bool) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	req, ok := b.pending[id]
	return req, ok
}

// PromptCLI blocks for human approval via stdin; deny-by-default on timeout for destructive actions.
func (b *Broker) PromptCLI(ctx context.Context, req Request, opts PromptOptions) (approved bool, err error) {
	if opts.Reader == nil {
		opts.Reader = os.Stdin
	}
	if opts.Writer == nil {
		opts.Writer = os.Stderr
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 5 * time.Minute
	}

	if auto := strings.TrimSpace(os.Getenv("AGENTGUARD_AUTO_DENY")); auto == "1" || strings.EqualFold(auto, "true") {
		b.Enqueue(req)
		b.Deny(req.ID)
		fmt.Fprintf(opts.Writer, "\nAgentGuard auto-denied approval [%s] (AGENTGUARD_AUTO_DENY)\n", req.ID)
		return false, nil
	}
	if auto := strings.TrimSpace(os.Getenv("AGENTGUARD_AUTO_APPROVE")); auto == "1" || strings.EqualFold(auto, "true") {
		b.Enqueue(req)
		b.Approve(req.ID)
		fmt.Fprintf(opts.Writer, "\nAgentGuard auto-approved [%s] (AGENTGUARD_AUTO_APPROVE)\n", req.ID)
		return true, nil
	}

	b.Enqueue(req)
	waitCh := make(chan bool, 1)
	b.mu.Lock()
	b.waiters[req.ID] = waitCh
	b.mu.Unlock()

	fmt.Fprintf(opts.Writer, "\nAgentGuard approval required [%s]\n", req.ID)
	fmt.Fprintf(opts.Writer, "  session:  %s\n", req.SessionID)
	fmt.Fprintf(opts.Writer, "  command:  %s\n", req.Proposal.Command)
	fmt.Fprintf(opts.Writer, "  decision: %s\n", req.Decision)
	fmt.Fprintf(opts.Writer, "Allow this action? [y/N] (auto-deny in %s): ", opts.Timeout)

	promptDone := make(chan bool, 1)
	go func() {
		reader := bufio.NewReader(opts.Reader)
		line, readErr := reader.ReadString('\n')
		if readErr != nil && readErr != io.EOF {
			promptDone <- false
			return
		}
		answer := strings.TrimSpace(strings.ToLower(line))
		promptDone <- answer == "y" || answer == "yes"
	}()

	timer := time.NewTimer(opts.Timeout)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		b.Deny(req.ID)
		return false, ctx.Err()
	case ok := <-waitCh:
		return ok, nil
	case approved := <-promptDone:
		if approved {
			b.Approve(req.ID)
			return true, nil
		}
		b.Deny(req.ID)
		return false, nil
	case <-timer.C:
		b.Deny(req.ID)
		fmt.Fprintf(opts.Writer, "\nApproval timed out; denying by default.\n")
		return false, nil
	}
}
