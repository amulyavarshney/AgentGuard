package session

import (
	"sync"
	"time"

	"github.com/google/uuid"
)

// Status describes the lifecycle state of a wrapped agent session.
type Status string

const (
	StatusActive  Status = "active"
	StatusEnded   Status = "ended"
	StatusPending Status = "pending"
)

// Session tracks a wrapped agent execution context.
type Session struct {
	ID            string    `json:"id"`
	Task          string    `json:"task,omitempty"`
	Environment   string    `json:"environment,omitempty"`
	Status        Status    `json:"status"`
	StartedAt     time.Time `json:"started_at"`
	EndedAt       *time.Time `json:"ended_at,omitempty"`
	AgentLauncher string    `json:"agent_launcher,omitempty"`
}

// Registry is an in-memory session registry for the control plane.
type Registry struct {
	mu       sync.RWMutex
	sessions map[string]Session
}

// NewRegistry creates an empty session registry.
func NewRegistry() *Registry {
	return &Registry{sessions: make(map[string]Session)}
}

// Create registers a new active session.
func (r *Registry) Create(task, environment, launcher string) Session {
	r.mu.Lock()
	defer r.mu.Unlock()

	s := Session{
		ID:            uuid.NewString(),
		Task:          task,
		Environment:   environment,
		Status:        StatusActive,
		StartedAt:     time.Now().UTC(),
		AgentLauncher: launcher,
	}
	r.sessions[s.ID] = s
	return s
}

// List returns all known sessions.
func (r *Registry) List() []Session {
	r.mu.RLock()
	defer r.mu.RUnlock()

	out := make([]Session, 0, len(r.sessions))
	for _, s := range r.sessions {
		out = append(out, s)
	}
	return out
}

// Get returns a session by ID.
func (r *Registry) Get(id string) (Session, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	s, ok := r.sessions[id]
	return s, ok
}

// End marks a session as ended.
func (r *Registry) End(id string) (Session, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	s, ok := r.sessions[id]
	if !ok {
		return Session{}, false
	}
	now := time.Now().UTC()
	s.Status = StatusEnded
	s.EndedAt = &now
	r.sessions[id] = s
	return s, true
}
