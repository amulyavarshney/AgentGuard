package main

import (
	"fmt"
	"os"

	"github.com/amulyavarshney/agentguard/cmd/agentguard/commands"
	"github.com/spf13/cobra"
)

func main() {
	if err := newRootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "agentguard",
		Short: "Runtime policy firewall and flight recorder for autonomous agents",
		Long:  "AgentGuard intercepts agent actions, enforces YAML policies, and records tamper-resistant audit events.",
	}
	root.PersistentFlags().String("config", "agentguard.yaml", "Path to agentguard.yaml")

	root.AddCommand(
		commands.NewRunCmd(),
		commands.NewExecCmd(),
		commands.NewPolicyCmd(),
		commands.NewSessionCmd(),
		commands.NewApproveCmd(),
		commands.NewServeCmd(),
		commands.NewShimCmd(),
	)
	return root
}
