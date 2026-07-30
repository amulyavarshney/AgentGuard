package credentials

import "github.com/amulyavarshney/agentguard/internal/model"

// ScopeMapper resolves credential references to blast-radius capability labels.
type ScopeMapper interface {
	Resolve(ref string) ([]string, error)
}

// AnnotateProposal attaches credential scope metadata to a proposal.
func AnnotateProposal(proposal model.ActionProposal, scope []string, ref string) model.ActionProposal {
	proposal.CredentialRef = ref
	proposal.CredentialScope = append([]string(nil), scope...)
	return proposal
}
