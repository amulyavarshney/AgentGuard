package commands

import (
	"os"

	"github.com/amulyavarshney/agentguard/internal/intercept"
	"github.com/spf13/cobra"
)

func NewShimCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:    "__shim__ <tool> [-- args...]",
		Hidden: true,
		Short:  "Internal shim client (invoked by PATH wrappers)",
		RunE: func(_ *cobra.Command, args []string) error {
			err := intercept.RunShimClient(args)
			if exitErr, ok := err.(*intercept.ExitError); ok {
				os.Exit(exitErr.Code)
			}
			return err
		},
	}
	return cmd
}
