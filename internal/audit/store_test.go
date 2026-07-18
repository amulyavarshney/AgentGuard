package audit

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/amulyavarshney/agentguard/internal/model"
)

func TestAppendEventBuildsHashChain(t *testing.T) {
	t.Parallel()

	store := openTestStore(t)
	defer store.Close()

	ctx := context.Background()
	sessionID := "sess-1"

	first, err := store.AppendEvent(ctx, AppendInput{
		Proposal: model.ActionProposal{
			ID:         "prop-1",
			SessionID:  sessionID,
			Timestamp:  time.Now().UTC(),
			ActionType: "shell",
			Command:    "echo hello",
		},
		Decision: model.PolicyAllow,
		Result:   "executed",
	})
	if err != nil {
		t.Fatalf("append first event: %v", err)
	}
	if first.PrevHash != genesisHash {
		t.Fatalf("first prev_hash = %q, want genesis", first.PrevHash)
	}
	if first.EventHash == "" {
		t.Fatal("first event_hash is empty")
	}

	second, err := store.AppendEvent(ctx, AppendInput{
		Proposal: model.ActionProposal{
			ID:         "prop-2",
			SessionID:  sessionID,
			ActionType: "filesystem",
			Command:    "rm -rf /tmp/foo",
		},
		Decision: model.PolicyBlock,
		Result:   "blocked",
	})
	if err != nil {
		t.Fatalf("append second event: %v", err)
	}
	if second.PrevHash != first.EventHash {
		t.Fatalf("second prev_hash = %q, want %q", second.PrevHash, first.EventHash)
	}

	if err := store.VerifySessionChain(ctx, sessionID); err != nil {
		t.Fatalf("verify chain: %v", err)
	}
}

func TestVerifySessionChainDetectsTampering(t *testing.T) {
	t.Parallel()

	store := openTestStore(t)
	defer store.Close()

	ctx := context.Background()
	sessionID := "sess-tamper"

	_, err := store.AppendEvent(ctx, AppendInput{
		Proposal: model.ActionProposal{
			ID:         "prop-1",
			SessionID:  sessionID,
			ActionType: "shell",
			Command:    "ls",
		},
		Decision: model.PolicyAllow,
	})
	if err != nil {
		t.Fatalf("append event: %v", err)
	}

	_, err = store.db.ExecContext(ctx, `UPDATE audit_events SET result = 'tampered' WHERE session_id = ?`, sessionID)
	if err != nil {
		t.Fatalf("tamper event: %v", err)
	}

	if err := store.VerifySessionChain(ctx, sessionID); err == nil {
		t.Fatal("expected tampering to break chain verification")
	}
}

func TestVerifyAllChainsAcrossSessions(t *testing.T) {
	t.Parallel()

	store := openTestStore(t)
	defer store.Close()

	ctx := context.Background()
	for _, sessionID := range []string{"sess-a", "sess-b"} {
		_, err := store.AppendEvent(ctx, AppendInput{
			Proposal: model.ActionProposal{
				ID:         "prop-" + sessionID,
				SessionID:  sessionID,
				ActionType: "http",
				Command:    "GET /health",
			},
			Decision: model.PolicyAllow,
		})
		if err != nil {
			t.Fatalf("append for %s: %v", sessionID, err)
		}
	}

	if err := store.VerifyAllChains(ctx); err != nil {
		t.Fatalf("verify all chains: %v", err)
	}
}

func TestListEventsReturnsOrderedTimeline(t *testing.T) {
	t.Parallel()

	store := openTestStore(t)
	defer store.Close()

	ctx := context.Background()
	sessionID := "sess-list"

	for i := 0; i < 3; i++ {
		_, err := store.AppendEvent(ctx, AppendInput{
			Proposal: model.ActionProposal{
				ID:         "prop",
				SessionID:  sessionID,
				ActionType: "shell",
				Command:    "step",
			},
			Decision: model.PolicyAllow,
		})
		if err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}

	events, err := store.ListEvents(ctx, sessionID)
	if err != nil {
		t.Fatalf("list events: %v", err)
	}
	if len(events) != 3 {
		t.Fatalf("got %d events, want 3", len(events))
	}
	for i := 1; i < len(events); i++ {
		if events[i].Sequence <= events[i-1].Sequence {
			t.Fatalf("events not ordered by sequence: %+v", events)
		}
		if events[i].PrevHash != events[i-1].EventHash {
			t.Fatalf("event %d prev_hash not linked to previous event_hash", i+1)
		}
	}
}

func openTestStore(t *testing.T) *Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.db")
	store, err := Open(path)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	return store
}
