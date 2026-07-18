package intent

import "github.com/amulyavarshney/agentguard/internal/model"

// Comparator checks whether an action aligns with the session task instruction.
type Comparator interface {
	Compare(task string, proposal model.ActionProposal) (Result, error)
}

// Result captures heuristic intent comparison output.
type Result struct {
	Aligned bool                 `json:"aligned"`
	Reasons []string             `json:"reasons,omitempty"`
	Verdict model.PolicyDecision `json:"verdict,omitempty"`
}

// StubComparator performs no analysis (always aligned).
type StubComparator struct{}

// Compare implements Comparator.
func (StubComparator) Compare(_ string, _ model.ActionProposal) (Result, error) {
	return Result{Aligned: true, Verdict: model.PolicyAllow}, nil
}
