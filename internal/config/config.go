package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config is the top-level AgentGuard configuration loaded from agentguard.yaml.
type Config struct {
	DataDir     string              `yaml:"data_dir"`
	PolicyDir   string              `yaml:"policy_dir"`
	API         APIConfig           `yaml:"api"`
	Profiles    []Profile           `yaml:"profiles,omitempty"`
	Credentials CredentialsConfig   `yaml:"credentials,omitempty"`
}

// APIConfig controls the local control-plane HTTP server.
type APIConfig struct {
	Listen string `yaml:"listen"`
}

// Profile represents a named local scope (team/org stand-in for MVP).
type Profile struct {
	Name        string `yaml:"name"`
	Environment string `yaml:"environment"`
}

// CredentialsConfig maps credential references to blast-radius capability labels.
type CredentialsConfig struct {
	AWSProfiles []AWSCredentialProfile `yaml:"aws_profiles,omitempty"`
	Postgres    []PostgresCredential   `yaml:"postgres,omitempty"`
	HTTPTokens  []HTTPTokenCredential  `yaml:"http_tokens,omitempty"`
}

// AWSCredentialProfile describes static capability labels for an AWS CLI profile.
type AWSCredentialProfile struct {
	Profile     string   `yaml:"profile"`
	Environment string   `yaml:"environment,omitempty"`
	ScopeLabels []string `yaml:"scope_labels"`
}

// PostgresCredential describes PostgreSQL role/host capability labels.
type PostgresCredential struct {
	ConnRef     string   `yaml:"conn_ref"`
	HostPattern string   `yaml:"host_pattern,omitempty"`
	Database    string   `yaml:"database,omitempty"`
	Role        string   `yaml:"role,omitempty"`
	Environment string   `yaml:"environment,omitempty"`
	ScopeLabels []string `yaml:"scope_labels"`
}

// HTTPTokenCredential treats bearer tokens as opaque with configured scope labels.
type HTTPTokenCredential struct {
	Ref           string   `yaml:"ref"`
	HeaderPattern string   `yaml:"header_pattern,omitempty"`
	ScopeLabels   []string `yaml:"scope_labels"`
}

// Default returns sensible defaults when no config file is present.
func Default() Config {
	return Config{
		DataDir:   ".agentguard",
		PolicyDir: "policies",
		API: APIConfig{
			Listen: "127.0.0.1:8787",
		},
	}
}

// Load reads configuration from path, falling back to defaults for missing fields.
func Load(path string) (Config, error) {
	cfg := Default()
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("parse config: %w", err)
	}
	if cfg.DataDir == "" {
		cfg.DataDir = Default().DataDir
	}
	if cfg.PolicyDir == "" {
		cfg.PolicyDir = Default().PolicyDir
	}
	if cfg.API.Listen == "" {
		cfg.API.Listen = Default().API.Listen
	}
	return cfg, nil
}

// AuditDBPath returns the SQLite path for the audit store.
func (c Config) AuditDBPath() string {
	return fmt.Sprintf("%s/audit.db", c.DataDir)
}

// ProfileEnvironment returns the environment tag for a named profile, if configured.
func (c Config) ProfileEnvironment(name string) string {
	for _, p := range c.Profiles {
		if p.Name == name {
			return p.Environment
		}
	}
	return ""
}
