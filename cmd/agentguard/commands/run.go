package commands

import (
	"fmt"
	"os"

	"github.com/amulyavarshney/agentguard/internal/intercept"
	"github.com/spf13/cobra"
)

var agentPresets = map[string][]string{
	"bash":   {"bash"},
	"sh":     {"sh"},
	"claude": {"claude"},
	"zsh":    {"zsh"},
}

func NewRunCmd() *cobra.Command {
	var task, environment string

	cmd := &cobra.Command{
		Use:   "run <agent>",
		Short: "Run a known agent launcher through AgentGuard",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig(cmd)
			if err != nil {
				return err
			}
			if err := ensureDataDir(cfg); err != nil {
				return err
			}

			agent := args[0]
			command, ok := agentPresets[agent]
			if !ok {
				command = []string{agent}
			}

			ic, err := intercept.NewGatewayInterceptor(cfg)
			if err != nil {
				return err
			}
			err = ic.Wrap(cmd.Context(), intercept.WrapOptions{
				Task:        task,
				Environment: environment,
				Command:     command,
			})
			if exitErr, ok := err.(*intercept.ExitError); ok {
				os.Exit(exitErr.Code)
			}
			return err
		},
	}

	cmd.Flags().StringVar(&task, "task", "", "Original user task instruction for intent comparison")
	cmd.Flags().StringVar(&environment, "env", "staging", "Target environment tag")
	return cmd
}

// ResolveAgentPreset returns the command argv for a known agent name.
func ResolveAgentPreset(agent string) ([]string, error) {
	if preset, ok := agentPresets[agent]; ok {
		return append([]string(nil), preset...), nil
	}
	if _, err := os.Stat(agent); err == nil {
		return []string{agent}, nil
	}
	return nil, fmt.Errorf("unknown agent %q (no preset; pass a binary path or use exec)", agent)
}
