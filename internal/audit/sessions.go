package audit

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"

	"github.com/amulyavarshney/agentguard/internal/model"
	"github.com/amulyavarshney/agentguard/internal/session"
)

// GetEvent returns a single audit event by ID.
func (s *Store) GetEvent(ctx context.Context, eventID string) (model.AuditEvent, error) {
	row := s.db.QueryRowContext(ctx, `
SELECT id, session_id, sequence, timestamp, proposal_json, decision,
       approvers_json, result, side_effects_json, prev_hash, event_hash
FROM audit_events
WHERE id = ?`, eventID)

	event, err := scanEvent(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return model.AuditEvent{}, fmt.Errorf("event %q not found", eventID)
		}
		return model.AuditEvent{}, fmt.Errorf("get event %q: %w", eventID, err)
	}
	return event, nil
}

// DeriveSessions reconstructs session metadata from audit events.
func (s *Store) DeriveSessions(ctx context.Context) ([]session.Session, error) {
	events, err := s.ListAllEvents(ctx, 1000)
	if err != nil {
		return nil, err
	}
	if len(events) == 0 {
		return []session.Session{}, nil
	}

	type agg struct {
		sess   session.Session
		latest int64
	}
	byID := map[string]*agg{}

	for _, ev := range events {
		cur, ok := byID[ev.SessionID]
		if !ok {
			task := ev.Proposal.IntentSummary
			if task == "" {
				task = ev.Proposal.Command
			}
			cur = &agg{
				sess: session.Session{
					ID:          ev.SessionID,
					Task:        task,
					Environment: ev.Proposal.Environment,
					Status:      session.StatusEnded,
					StartedAt:   ev.Timestamp,
				},
				latest: ev.Sequence,
			}
			byID[ev.SessionID] = cur
		}
		if ev.Sequence >= cur.latest {
			cur.latest = ev.Sequence
			ended := ev.Timestamp
			cur.sess.EndedAt = &ended
		}
		if cur.sess.StartedAt.After(ev.Timestamp) {
			cur.sess.StartedAt = ev.Timestamp
		}
		if cur.sess.Task == "" && ev.Proposal.IntentSummary != "" {
			cur.sess.Task = ev.Proposal.IntentSummary
		}
		if cur.sess.Environment == "" && ev.Proposal.Environment != "" {
			cur.sess.Environment = ev.Proposal.Environment
		}
	}

	out := make([]session.Session, 0, len(byID))
	for _, a := range byID {
		out = append(out, a.sess)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].StartedAt.After(out[j].StartedAt)
	})
	return out, nil
}
