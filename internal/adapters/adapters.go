package adapters

import (
	"context"

	"github.com/amulyavarshney/agentguard/internal/model"
)

// Adapter normalizes a target-specific action into an ActionProposal.
type Adapter interface {
	Classify(ctx context.Context, raw map[string]any) (model.ActionProposal, error)
}

// Registry holds named adapters for shell, filesystem, http, postgres, and aws.
type Registry struct {
	Shell      Adapter
	Filesystem Adapter
	HTTP       Adapter
	Postgres   Adapter
	AWS        Adapter
}

// DefaultRegistry returns adapters for all gated action types.
func DefaultRegistry(allowlist []string) Registry {
	fs := NewFilesystemAdapter(allowlist)
	return Registry{
		Shell:      NewShellAdapter(fs),
		Filesystem: fs,
		HTTP:       NewHTTPAdapter(),
		Postgres:   NewPostgresAdapter(),
		AWS:        NewAWSAdapter(),
	}
}
