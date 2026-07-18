package commands

import (
	"fmt"
	"os"

	"github.com/amulyavarshney/agentguard/internal/intercept"
	"github.com/spf13/cobra"
)

func NewExecCmd() *cobra.Command {
	var task, environment string

	cmd := &cobra.Command{
		Use:   "exec -- <command...>",
		Short: "Wrap an arbitrary command through AgentGuard",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return fmt.Errorf("exec requires a command after --")
			}
			cfg, err := loadConfig(cmd)
			if err != nil {
				return err
			}
			if err := ensureDataDir(cfg); err != nil {
				return err
			}

			ic, err := intercept.NewGatewayInterceptor(cfg)
			if err != nil {
				return err
			}
			err = ic.Wrap(cmd.Context(), intercept.WrapOptions{
				Task:        task,
				Environment: environment,
				Command:     args,
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
