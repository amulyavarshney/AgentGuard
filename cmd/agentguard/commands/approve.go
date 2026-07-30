package commands

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

func NewApproveCmd() *cobra.Command {
	var deny bool
	cmd := &cobra.Command{
		Use:   "approve <request-id>",
		Short: "Approve or deny a pending gated action via the local control plane",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig(cmd)
			if err != nil {
				return err
			}

			action := "approve"
			if deny {
				action = "deny"
			}
			base := strings.TrimRight("http://"+cfg.API.Listen, "/")
			url := fmt.Sprintf("%s/api/v1/approvals/%s/%s", base, args[0], action)

			client := &http.Client{Timeout: 10 * time.Second}
			req, err := http.NewRequest(http.MethodPost, url, nil)
			if err != nil {
				return err
			}
			resp, err := client.Do(req)
			if err != nil {
				return fmt.Errorf("control plane unreachable at %s — is `agentguard serve` running? (%w)", base, err)
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			if resp.StatusCode >= 300 {
				return fmt.Errorf("approval %s failed (%d): %s", action, resp.StatusCode, strings.TrimSpace(string(body)))
			}

			var out map[string]any
			if err := json.Unmarshal(body, &out); err == nil {
				fmt.Printf("%s request %s\n", action+"d", args[0])
				return nil
			}
			fmt.Printf("%s\n", string(body))
			return nil
		},
	}
	cmd.Flags().BoolVar(&deny, "deny", false, "Deny the request instead of approving")
	return cmd
}
