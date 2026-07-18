package policy

import (
	"fmt"

	"github.com/amulyavarshney/agentguard/internal/model"
)

var validScopes = map[string]struct{}{
	"agent": {},
	"repo":  {},
	"team":  {},
	"org":   {},
}

var validActions = map[string]struct{}{
	string(model.PolicyAllow):            {},
	string(model.PolicyBlock):            {},
	string(model.PolicyRequireApproval):  {},
	string(model.PolicyPauseAndEscalate): {},
}

// ValidateDocument performs structural validation on a policy document.
func ValidateDocument(doc Document) error {
	if len(doc.Rules) == 0 {
		return fmt.Errorf("policy must contain at least one rule")
	}
	seen := make(map[string]struct{}, len(doc.Rules))
	for i, rule := range doc.Rules {
		if err := validateRule(rule, i); err != nil {
			return err
		}
		if _, dup := seen[rule.ID]; dup {
			return fmt.Errorf("duplicate rule id: %s", rule.ID)
		}
		seen[rule.ID] = struct{}{}
	}
	return nil
}

func validateRule(rule Rule, index int) error {
	prefix := fmt.Sprintf("rule[%d]", index)
	if rule.ID == "" {
		return fmt.Errorf("%s: missing id", prefix)
	}
	if rule.Scope != "" {
		if _, ok := validScopes[rule.Scope]; !ok {
			return fmt.Errorf("%s (%s): invalid scope %q", prefix, rule.ID, rule.Scope)
		}
	}
	hasEffect := rule.Deny.AgentInitiatedDeletion ||
		rule.Require.HumanApproval ||
		rule.Action != ""
	if !hasEffect {
		return fmt.Errorf("%s (%s): must specify deny, require, or action", prefix, rule.ID)
	}
	if rule.Action != "" {
		if _, ok := validActions[rule.Action]; !ok {
			return fmt.Errorf("%s (%s): invalid action %q", prefix, rule.ID, rule.Action)
		}
	}
	if rule.Require.Approvers < 0 {
		return fmt.Errorf("%s (%s): approvers must be >= 0", prefix, rule.ID)
	}
	if err := validateMatch(rule.Match, prefix, rule.ID); err != nil {
		return err
	}
	return nil
}

func validateMatch(m MatchCriteria, prefix, id string) error {
	if m.AffectedRecordsGT != nil && *m.AffectedRecordsGT < 0 {
		return fmt.Errorf("%s (%s): affected_records_gt must be >= 0", prefix, id)
	}
	if m.EgressBytesGT != nil && *m.EgressBytesGT < 0 {
		return fmt.Errorf("%s (%s): egress_bytes_gt must be >= 0", prefix, id)
	}
	for _, at := range m.ActionTypes {
		if at == "" {
			return fmt.Errorf("%s (%s): action_types contains empty value", prefix, id)
		}
	}
	for _, a := range m.Actions {
		if a == "" {
			return fmt.Errorf("%s (%s): actions contains empty value", prefix, id)
		}
	}
	for _, r := range m.Resources {
		if r == "" {
			return fmt.Errorf("%s (%s): resources contains empty value", prefix, id)
		}
	}
	return nil
}
