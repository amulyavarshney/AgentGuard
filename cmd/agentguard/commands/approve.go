package commands

import (
	"fmt"

	"github.com/amulyavarshney/agentguard/internal/approval"
	"github.com/spf13/cobra"
)

func NewApproveCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "approve <request-id>",
		Short: "Approve a pending gated action",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, err := loadConfig(cmd)
			if err != nil {
				return err
			}

			broker := approval.NewBroker()
			req, ok := broker.Approve(args[0])
			if !ok {
				return fmt.Errorf("approval request %q not found (approval broker not yet wired to live queue)", args[0])
			}
			fmt.Printf("approved request %s for session %s\n", req.ID, req.SessionID)
			return nil
		},
	}
	return cmd
}
