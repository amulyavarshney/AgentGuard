package audit

import (
	"context"
	"testing"
	"time"

	"github.com/amulyavarshney/agentguard/internal/model"
)

func TestGetEventAndDeriveSessions(t *testing.T) {
	t.Parallel()

	store := openTestStore(t)
	defer store.Close()

	ctx := context.Background()
	sessionID := "sess-derive"

	ev, err := store.AppendEvent(ctx, AppendInput{
		Proposal: model.ActionProposal{
			ID:            "prop-1",
			SessionID:     sessionID,
			Timestamp:     time.Now().UTC(),
			IntentSummary: "fix auth error in staging",
			ActionType:    "aws",
			Command:       "aws rds delete-db-instance --db-instance-identifier prod-db",
			Environment:   "staging",
		},
		Decision: model.PolicyBlock,
		Result:   "blocked",
	})
	if err != nil {
		t.Fatalf("append: %v", err)
	}

	got, err := store.GetEvent(ctx, ev.ID)
	if err != nil {
		t.Fatalf("get event: %v", err)
	}
	if got.ID != ev.ID {
		t.Fatalf("event id = %q, want %q", got.ID, ev.ID)
	}

	sessions, err := store.DeriveSessions(ctx)
	if err != nil {
		t.Fatalf("derive sessions: %v", err)
	}
	if len(sessions) != 1 {
		t.Fatalf("sessions = %d, want 1", len(sessions))
	}
	if sessions[0].ID != sessionID {
		t.Fatalf("session id = %q, want %q", sessions[0].ID, sessionID)
	}
	if sessions[0].Task != "fix auth error in staging" {
		t.Fatalf("task = %q", sessions[0].Task)
	}
}

func TestGetEventNotFound(t *testing.T) {
	t.Parallel()

	store := openTestStore(t)
	defer store.Close()

	_, err := store.GetEvent(context.Background(), "missing")
	if err == nil {
		t.Fatal("expected error for missing event")
	}
}
