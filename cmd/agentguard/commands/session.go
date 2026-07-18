package commands

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/amulyavarshney/agentguard/internal/audit"
	"github.com/amulyavarshney/agentguard/internal/session"
	"github.com/spf13/cobra"
)

func NewSessionCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "session",
		Short: "Session lifecycle commands",
	}
	cmd.AddCommand(newSessionListCmd())
	cmd.AddCommand(newSessionReplayCmd())
	cmd.AddCommand(newSessionVerifyCmd())
	return cmd
}

func openAuditStore(cmd *cobra.Command) (*audit.Store, error) {
	cfg, err := loadConfig(cmd)
	if err != nil {
		return nil, err
	}
	if err := ensureDataDir(cfg); err != nil {
		return nil, err
	}
	store, err := audit.Open(cfg.AuditDBPath())
	if err != nil {
		return nil, fmt.Errorf("open audit store: %w", err)
	}
	return store, nil
}

func newSessionListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List agent sessions recorded in the audit log",
		RunE: func(cmd *cobra.Command, _ []string) error {
			store, err := openAuditStore(cmd)
			if err != nil {
				return err
			}
			defer store.Close()

			sessions, err := store.DeriveSessions(cmd.Context())
			if err != nil {
				return fmt.Errorf("list sessions: %w", err)
			}
			if sessions == nil {
				sessions = []session.Session{}
			}

			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(sessions)
		},
	}
	return cmd
}

func newSessionReplayCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "replay <session-id>",
		Short: "Print hash-chained audit timeline for a session",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := openAuditStore(cmd)
			if err != nil {
				return err
			}
			defer store.Close()

			events, err := store.ListEvents(cmd.Context(), args[0])
			if err != nil {
				return fmt.Errorf("list events: %w", err)
			}
			if len(events) == 0 {
				return fmt.Errorf("no audit events for session %q", args[0])
			}

			type timelineEntry struct {
				ID        string `json:"id"`
				Sequence  int64  `json:"sequence"`
				Decision  string `json:"decision"`
				Result    string `json:"result"`
				Command   string `json:"command"`
				PrevHash  string `json:"prev_hash"`
				EventHash string `json:"event_hash"`
			}
			out := make([]timelineEntry, 0, len(events))
			for _, ev := range events {
				out = append(out, timelineEntry{
					ID:        ev.ID,
					Sequence:  ev.Sequence,
					Decision:  string(ev.Decision),
					Result:    ev.Result,
					Command:   ev.Proposal.Command,
					PrevHash:  ev.PrevHash,
					EventHash: ev.EventHash,
				})
			}

			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(out)
		},
	}
	return cmd
}

func newSessionVerifyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "verify <session-id>",
		Short: "Verify hash-chain integrity for a session timeline",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := openAuditStore(cmd)
			if err != nil {
				return err
			}
			defer store.Close()

			if err := store.VerifySessionChain(cmd.Context(), args[0]); err != nil {
				return fmt.Errorf("hash chain invalid: %w", err)
			}
			events, err := store.ListEvents(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			fmt.Printf("session %s: hash chain valid (%d events)\n", args[0], len(events))
			if len(events) > 0 {
				fmt.Printf("  head hash: %s\n", events[len(events)-1].EventHash)
			}
			return nil
		},
	}
	return cmd
}
