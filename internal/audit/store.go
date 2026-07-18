package audit

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/amulyavarshney/agentguard/internal/model"
	"github.com/google/uuid"
	_ "modernc.org/sqlite"
)

// Store is an append-only SQLite audit log with a per-session hash chain.
type Store struct {
	db *sql.DB
}

// Open opens or creates an audit store at dbPath.
func Open(dbPath string) (*Store, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	if err := configureDB(db); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

func configureDB(db *sql.DB) error {
	pragmas := []string{
		"PRAGMA journal_mode=WAL;",
		"PRAGMA foreign_keys=ON;",
	}
	for _, p := range pragmas {
		if _, err := db.Exec(p); err != nil {
			return fmt.Errorf("pragma: %w", err)
		}
	}
	schema := `
CREATE TABLE IF NOT EXISTS audit_events (
	id TEXT PRIMARY KEY,
	session_id TEXT NOT NULL,
	sequence INTEGER NOT NULL,
	timestamp TEXT NOT NULL,
	proposal_json TEXT NOT NULL,
	decision TEXT NOT NULL,
	approvers_json TEXT NOT NULL DEFAULT '[]',
	result TEXT NOT NULL DEFAULT '',
	side_effects_json TEXT NOT NULL DEFAULT '{}',
	prev_hash TEXT NOT NULL,
	event_hash TEXT NOT NULL,
	UNIQUE(session_id, sequence)
);
CREATE INDEX IF NOT EXISTS idx_audit_session ON audit_events(session_id, sequence);
`
	if _, err := db.Exec(schema); err != nil {
		return fmt.Errorf("migrate schema: %w", err)
	}
	return nil
}

// Close closes the underlying database.
func (s *Store) Close() error {
	if s.db == nil {
		return nil
	}
	return s.db.Close()
}

// AppendEvent appends a new audit event, linking it to the previous event hash for the session.
func (s *Store) AppendEvent(ctx context.Context, input AppendInput) (model.AuditEvent, error) {
	if input.Proposal.SessionID == "" {
		return model.AuditEvent{}, errors.New("proposal session_id is required")
	}
	if !input.Decision.Valid() {
		return model.AuditEvent{}, fmt.Errorf("invalid decision: %q", input.Decision)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return model.AuditEvent{}, fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	prevHash, seq, err := lastChainLink(ctx, tx, input.Proposal.SessionID)
	if err != nil {
		return model.AuditEvent{}, err
	}

	ts := input.Timestamp
	if ts.IsZero() {
		ts = time.Now().UTC()
	}

	event := model.AuditEvent{
		ID:          uuid.NewString(),
		SessionID:   input.Proposal.SessionID,
		Sequence:    seq + 1,
		Timestamp:   ts.UTC(),
		Proposal:    input.Proposal,
		Decision:    input.Decision,
		Approvers:   append([]string(nil), input.Approvers...),
		Result:      input.Result,
		SideEffects: cloneMap(input.SideEffects),
		PrevHash:    prevHash,
	}
	eventHash, err := computeEventHash(event)
	if err != nil {
		return model.AuditEvent{}, err
	}
	event.EventHash = eventHash

	if err := insertEvent(ctx, tx, event); err != nil {
		return model.AuditEvent{}, err
	}
	if err := tx.Commit(); err != nil {
		return model.AuditEvent{}, fmt.Errorf("commit: %w", err)
	}
	return event, nil
}

// AppendInput is the data required to append an audit event.
type AppendInput struct {
	Proposal    model.ActionProposal
	Decision    model.PolicyDecision
	Approvers   []string
	Result      string
	SideEffects map[string]any
	Timestamp   time.Time
}

func lastChainLink(ctx context.Context, tx *sql.Tx, sessionID string) (prevHash string, lastSeq int64, err error) {
	row := tx.QueryRowContext(ctx, `
SELECT event_hash, sequence FROM audit_events
WHERE session_id = ?
ORDER BY sequence DESC
LIMIT 1`, sessionID)
	var hash sql.NullString
	if err := row.Scan(&hash, &lastSeq); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return genesisHash, 0, nil
		}
		return "", 0, fmt.Errorf("query last event: %w", err)
	}
	if !hash.Valid {
		return genesisHash, lastSeq, nil
	}
	return hash.String, lastSeq, nil
}

func insertEvent(ctx context.Context, tx *sql.Tx, event model.AuditEvent) error {
	proposalJSON, err := json.Marshal(event.Proposal)
	if err != nil {
		return fmt.Errorf("marshal proposal: %w", err)
	}
	approversJSON, err := json.Marshal(event.Approvers)
	if err != nil {
		return fmt.Errorf("marshal approvers: %w", err)
	}
	sideEffectsJSON, err := json.Marshal(event.SideEffects)
	if err != nil {
		return fmt.Errorf("marshal side effects: %w", err)
	}

	_, err = tx.ExecContext(ctx, `
INSERT INTO audit_events (
	id, session_id, sequence, timestamp, proposal_json, decision,
	approvers_json, result, side_effects_json, prev_hash, event_hash
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		event.ID,
		event.SessionID,
		event.Sequence,
		event.Timestamp.UTC().Format(timeRFC3339Nano),
		string(proposalJSON),
		string(event.Decision),
		string(approversJSON),
		event.Result,
		string(sideEffectsJSON),
		event.PrevHash,
		event.EventHash,
	)
	if err != nil {
		return fmt.Errorf("insert event: %w", err)
	}
	return nil
}

// ListEvents returns audit events for a session ordered by sequence.
func (s *Store) ListEvents(ctx context.Context, sessionID string) ([]model.AuditEvent, error) {
	return s.listEvents(ctx, sessionID, 0)
}

// ListAllEvents returns all audit events ordered by timestamp then sequence.
func (s *Store) ListAllEvents(ctx context.Context, limit int) ([]model.AuditEvent, error) {
	return s.listEvents(ctx, "", limit)
}

// ListEventsByDecision returns events filtered by decision, newest first.
func (s *Store) ListEventsByDecision(ctx context.Context, decision model.PolicyDecision, limit int) ([]model.AuditEvent, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT id, session_id, sequence, timestamp, proposal_json, decision,
       approvers_json, result, side_effects_json, prev_hash, event_hash
FROM audit_events
WHERE decision = ?
ORDER BY timestamp DESC, sequence DESC
LIMIT ?`, string(decision), limit)
	if err != nil {
		return nil, fmt.Errorf("query events by decision: %w", err)
	}
	defer rows.Close()

	var events []model.AuditEvent
	for rows.Next() {
		event, err := scanEvent(rows)
		if err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate events: %w", err)
	}
	if events == nil {
		events = []model.AuditEvent{}
	}
	return events, nil
}

func (s *Store) listEvents(ctx context.Context, sessionID string, limit int) ([]model.AuditEvent, error) {
	if limit <= 0 {
		limit = 100
	}
	var (
		rows *sql.Rows
		err  error
	)
	if sessionID == "" {
		rows, err = s.db.QueryContext(ctx, `
SELECT id, session_id, sequence, timestamp, proposal_json, decision,
       approvers_json, result, side_effects_json, prev_hash, event_hash
FROM audit_events
ORDER BY timestamp ASC, sequence ASC
LIMIT ?`, limit)
	} else {
		rows, err = s.db.QueryContext(ctx, `
SELECT id, session_id, sequence, timestamp, proposal_json, decision,
       approvers_json, result, side_effects_json, prev_hash, event_hash
FROM audit_events
WHERE session_id = ?
ORDER BY sequence ASC`, sessionID)
	}
	if err != nil {
		return nil, fmt.Errorf("query events: %w", err)
	}
	defer rows.Close()

	var events []model.AuditEvent
	for rows.Next() {
		event, err := scanEvent(rows)
		if err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate events: %w", err)
	}
	return events, nil
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanEvent(row rowScanner) (model.AuditEvent, error) {
	var (
		event         model.AuditEvent
		ts            string
		proposalJSON  string
		decision      string
		approversJSON string
		sideEffects   string
	)
	if err := row.Scan(
		&event.ID,
		&event.SessionID,
		&event.Sequence,
		&ts,
		&proposalJSON,
		&decision,
		&approversJSON,
		&event.Result,
		&sideEffects,
		&event.PrevHash,
		&event.EventHash,
	); err != nil {
		return model.AuditEvent{}, fmt.Errorf("scan event: %w", err)
	}
	parsed, err := time.Parse(timeRFC3339Nano, ts)
	if err != nil {
		return model.AuditEvent{}, fmt.Errorf("parse timestamp: %w", err)
	}
	event.Timestamp = parsed
	event.Decision = model.PolicyDecision(decision)
	if err := json.Unmarshal([]byte(proposalJSON), &event.Proposal); err != nil {
		return model.AuditEvent{}, fmt.Errorf("unmarshal proposal: %w", err)
	}
	if err := json.Unmarshal([]byte(approversJSON), &event.Approvers); err != nil {
		return model.AuditEvent{}, fmt.Errorf("unmarshal approvers: %w", err)
	}
	if err := json.Unmarshal([]byte(sideEffects), &event.SideEffects); err != nil {
		return model.AuditEvent{}, fmt.Errorf("unmarshal side effects: %w", err)
	}
	return event, nil
}

// VerifySessionChain checks hash-chain integrity for a session.
func (s *Store) VerifySessionChain(ctx context.Context, sessionID string) error {
	events, err := s.ListEvents(ctx, sessionID)
	if err != nil {
		return err
	}
	return verifyEvents(events)
}

// VerifyAllChains checks hash-chain integrity for every session.
func (s *Store) VerifyAllChains(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx, `SELECT DISTINCT session_id FROM audit_events ORDER BY session_id`)
	if err != nil {
		return fmt.Errorf("list sessions: %w", err)
	}
	defer rows.Close()

	var sessionIDs []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return fmt.Errorf("scan session id: %w", err)
		}
		sessionIDs = append(sessionIDs, id)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate sessions: %w", err)
	}
	for _, id := range sessionIDs {
		if err := s.VerifySessionChain(ctx, id); err != nil {
			return fmt.Errorf("session %s: %w", id, err)
		}
	}
	return nil
}

func verifyEvents(events []model.AuditEvent) error {
	var expectedPrev = genesisHash
	for i, event := range events {
		if event.PrevHash != expectedPrev {
			return fmt.Errorf("event %d: prev_hash mismatch (got %q, want %q)", i+1, event.PrevHash, expectedPrev)
		}
		computed, err := computeEventHash(event)
		if err != nil {
			return fmt.Errorf("event %d: compute hash: %w", i+1, err)
		}
		if computed != event.EventHash {
			return fmt.Errorf("event %d: event_hash mismatch", i+1)
		}
		expectedPrev = event.EventHash
	}
	return nil
}

func cloneMap(src map[string]any) map[string]any {
	if len(src) == 0 {
		return nil
	}
	dst := make(map[string]any, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}
