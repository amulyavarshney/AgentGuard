package commands

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/amulyavarshney/agentguard/internal/model"
	"github.com/amulyavarshney/agentguard/internal/policy"
	"github.com/spf13/cobra"
)

func NewPolicyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "policy",
		Short: "Policy file utilities",
	}
	cmd.AddCommand(newPolicyValidateCmd())
	cmd.AddCommand(newPolicySaveRuleCmd())
	return cmd
}

func newPolicyValidateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "validate <policy-file>",
		Short: "Validate a policy YAML file structure",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			path := args[0]
			if err := policy.ValidateFile(path); err != nil {
				return fmt.Errorf("policy validation failed: %w", err)
			}
			fmt.Printf("policy %s is valid\n", path)
			return nil
		},
	}
	return cmd
}

func newPolicySaveRuleCmd() *cobra.Command {
	var (
		scope        string
		scopeID      string
		decision     string
		reason       string
		sessionID    string
		proposalFile string
	)

	cmd := &cobra.Command{
		Use:   "save-rule",
		Short: "Save an intervention as a permanent learned policy rule",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := loadConfig(cmd)
			if err != nil {
				return err
			}
			if proposalFile == "" {
				return fmt.Errorf("--proposal is required")
			}
			data, err := os.ReadFile(proposalFile)
			if err != nil {
				return fmt.Errorf("read proposal: %w", err)
			}
			var proposal model.ActionProposal
			if err := json.Unmarshal(data, &proposal); err != nil {
				return fmt.Errorf("parse proposal: %w", err)
			}
			path, err := policy.SaveLearnedRule(cfg.PolicyDir, policy.SaveRuleInput{
				Proposal:  proposal,
				Scope:     scope,
				ScopeID:   scopeID,
				Decision:  model.PolicyDecision(decision),
				Reason:    reason,
				SessionID: sessionID,
			})
			if err != nil {
				return fmt.Errorf("save learned rule: %w", err)
			}
			fmt.Printf("saved learned rule to %s\n", path)
			return nil
		},
	}
	cmd.Flags().StringVar(&scope, "scope", "org", "rule scope: agent, repo, team, or org")
	cmd.Flags().StringVar(&scopeID, "scope-id", "", "scope identifier (required for agent, repo, team)")
	cmd.Flags().StringVar(&decision, "decision", "block", "decision to enforce: block or require_approval")
	cmd.Flags().StringVar(&reason, "reason", "", "human-readable reason for the intervention")
	cmd.Flags().StringVar(&sessionID, "session-id", "", "source session id from intervention")
	cmd.Flags().StringVar(&proposalFile, "proposal", "", "path to ActionProposal JSON from intervention")
	return cmd
}
