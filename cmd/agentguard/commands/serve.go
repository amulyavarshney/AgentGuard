package commands

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/amulyavarshney/agentguard/internal/api"
	"github.com/amulyavarshney/agentguard/internal/approval"
	"github.com/amulyavarshney/agentguard/internal/audit"
	"github.com/amulyavarshney/agentguard/internal/policy"
	"github.com/amulyavarshney/agentguard/internal/session"
	"github.com/spf13/cobra"
)

func NewServeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Start the local control-plane API and web console",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := loadConfig(cmd)
			if err != nil {
				return err
			}
			if err := ensureDataDir(cfg); err != nil {
				return err
			}

			store, err := audit.Open(cfg.AuditDBPath())
			if err != nil {
				return fmt.Errorf("open audit store: %w", err)
			}
			defer store.Close()

			policyRegistry, err := policy.NewRegistry(cfg.PolicyDir, cfg.DataDir)
			if err != nil {
				return fmt.Errorf("policy registry: %w", err)
			}

			sessions := session.NewRegistry()
			approvals := approval.NewBroker()
			server := api.NewServer(api.Options{
				Listen:    cfg.API.Listen,
				PolicyDir: cfg.PolicyDir,
			}, sessions, store, approvals, policyRegistry)

			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer stop()

			errCh := make(chan error, 1)
			go func() {
				fmt.Fprintf(os.Stderr, "agentguard listening on http://%s\n", cfg.API.Listen)
				fmt.Fprintf(os.Stderr, "  API:     http://%s/api/v1/\n", cfg.API.Listen)
				fmt.Fprintf(os.Stderr, "  Console: http://%s/\n", cfg.API.Listen)
				errCh <- server.ListenAndServe()
			}()

			select {
			case <-ctx.Done():
				shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				_ = server.Shutdown(shutdownCtx)
				return nil
			case err := <-errCh:
				if err != nil && err != context.Canceled {
					return err
				}
				return nil
			}
		},
	}
	return cmd
}
