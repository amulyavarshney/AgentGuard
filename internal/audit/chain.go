package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/amulyavarshney/agentguard/internal/model"
)

const genesisHash = "0000000000000000000000000000000000000000000000000000000000000000"

type hashPayload struct {
	ID          string               `json:"id"`
	SessionID   string               `json:"session_id"`
	Sequence    int64                `json:"sequence"`
	Timestamp   string               `json:"timestamp"`
	Proposal    model.ActionProposal `json:"proposal"`
	Decision    model.PolicyDecision `json:"decision"`
	Approvers   []string             `json:"approvers,omitempty"`
	Result      string               `json:"result,omitempty"`
	SideEffects map[string]any       `json:"side_effects,omitempty"`
	PrevHash    string               `json:"prev_hash"`
}

func computeEventHash(event model.AuditEvent) (string, error) {
	payload := hashPayload{
		ID:          event.ID,
		SessionID:   event.SessionID,
		Sequence:    event.Sequence,
		Timestamp:   event.Timestamp.UTC().Format(timeRFC3339Nano),
		Proposal:    event.Proposal,
		Decision:    event.Decision,
		Approvers:   event.Approvers,
		Result:      event.Result,
		SideEffects: event.SideEffects,
		PrevHash:    event.PrevHash,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshal hash payload: %w", err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

const timeRFC3339Nano = "2006-01-02T15:04:05.999999999Z07:00"
