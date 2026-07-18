package credentials

import "github.com/amulyavarshney/agentguard/internal/model"

// ScopeMapper resolves credential references to blast-radius capability labels.
type ScopeMapper interface {
	Resolve(ref string) ([]string, error)
}

// StubScopeMapper returns empty scope until AWS/PG introspection is implemented.
type StubScopeMapper struct{}

// Resolve implements ScopeMapper.
func (StubScopeMapper) Resolve(_ string) ([]string, error) {
	return nil, nil
}

// AnnotateProposal attaches credential scope metadata to a proposal.
func AnnotateProposal(proposal model.ActionProposal, scope []string, ref string) model.ActionProposal {
	proposal.CredentialRef = ref
	proposal.CredentialScope = append([]string(nil), scope...)
	return proposal
}
