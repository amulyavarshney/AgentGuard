package commands

import (
	"fmt"
	"os"

	"github.com/amulyavarshney/agentguard/internal/config"
	"github.com/spf13/cobra"
)

func loadConfig(cmd *cobra.Command) (config.Config, error) {
	path, err := cmd.Root().PersistentFlags().GetString("config")
	if err != nil {
		return config.Config{}, err
	}
	if _, statErr := os.Stat(path); os.IsNotExist(statErr) {
		return config.Default(), nil
	}
	cfg, err := config.Load(path)
	if err != nil {
		return config.Config{}, fmt.Errorf("load config: %w", err)
	}
	return cfg, nil
}

func ensureDataDir(cfg config.Config) error {
	return os.MkdirAll(cfg.DataDir, 0o755)
}
