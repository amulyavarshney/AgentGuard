package credentials

import (
	"path/filepath"
	"strings"

	"github.com/amulyavarshney/agentguard/internal/config"
)

// ConfigMapper resolves credential references using agentguard.yaml labels.
type ConfigMapper struct {
	cfg config.Config
}

// NewConfigMapper builds a scope mapper from AgentGuard configuration.
func NewConfigMapper(cfg config.Config) *ConfigMapper {
	return &ConfigMapper{cfg: cfg}
}

// Resolve implements ScopeMapper for explicit credential refs (aws:profile, pg:..., http:...).
func (m *ConfigMapper) Resolve(ref string) ([]string, error) {
	if ref == "" {
		return nil, nil
	}
	switch {
	case strings.HasPrefix(ref, "aws:"):
		return m.awsScope(strings.TrimPrefix(ref, "aws:")), nil
	case strings.HasPrefix(ref, "pg:"):
		return m.postgresScopeByRef(ref), nil
	case strings.HasPrefix(ref, "http:"):
		return m.httpScopeByRef(strings.TrimPrefix(ref, "http:")), nil
	default:
		return nil, nil
	}
}

// ResolveAWS returns credential ref, scope labels, and optional environment override.
func (m *ConfigMapper) ResolveAWS(profile string) (ref string, scope []string, environment string) {
	if profile == "" {
		profile = "default"
	}
	ref = "aws:" + profile
	scope = m.awsScope(profile)
	for _, p := range m.cfg.Credentials.AWSProfiles {
		if p.Profile == profile {
			return ref, append([]string(nil), p.ScopeLabels...), p.Environment
		}
	}
	env := m.cfg.ProfileEnvironment(profile)
	return ref, scope, env
}

// ResolvePostgres returns credential ref, scope labels, and optional environment override.
func (m *ConfigMapper) ResolvePostgres(host, database, role string) (ref string, scope []string, environment string) {
	host = strings.TrimSpace(host)
	database = strings.TrimSpace(database)
	role = strings.TrimSpace(role)
	if role == "" {
		role = "unknown"
	}
	if host == "" {
		host = "localhost"
	}
	if database == "" {
		database = "postgres"
	}
	ref = "pg:" + role + "@" + host + "/" + database

	for _, pg := range m.cfg.Credentials.Postgres {
		if pg.Role != "" && !strings.EqualFold(pg.Role, role) {
			continue
		}
		if pg.Database != "" && !strings.EqualFold(pg.Database, database) {
			continue
		}
		if pg.HostPattern != "" && !hostMatchesPattern(host, pg.HostPattern) {
			continue
		}
		if pg.ConnRef != "" {
			ref = "pg:" + pg.ConnRef
		}
		return ref, append([]string(nil), pg.ScopeLabels...), pg.Environment
	}
	return ref, nil, ""
}

// ResolveHTTPAuth matches Authorization headers to configured opaque bearer scopes.
func (m *ConfigMapper) ResolveHTTPAuth(authHeader string) (ref string, scope []string) {
	authHeader = strings.TrimSpace(authHeader)
	if authHeader == "" {
		return "", nil
	}
	for _, token := range m.cfg.Credentials.HTTPTokens {
		if token.Ref == "" {
			continue
		}
		if token.HeaderPattern == "" || headerMatchesPattern(authHeader, token.HeaderPattern) {
			return "http:" + token.Ref, append([]string(nil), token.ScopeLabels...)
		}
	}
	// Opaque bearer without configured scope — ref only.
	if strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
		return "http:bearer-opaque", nil
	}
	return "", nil
}

func (m *ConfigMapper) awsScope(profile string) []string {
	for _, p := range m.cfg.Credentials.AWSProfiles {
		if p.Profile == profile {
			return append([]string(nil), p.ScopeLabels...)
		}
	}
	return nil
}

func (m *ConfigMapper) postgresScopeByRef(ref string) []string {
	connRef := strings.TrimPrefix(ref, "pg:")
	for _, pg := range m.cfg.Credentials.Postgres {
		if pg.ConnRef == connRef {
			return append([]string(nil), pg.ScopeLabels...)
		}
	}
	return nil
}

func (m *ConfigMapper) httpScopeByRef(name string) []string {
	for _, token := range m.cfg.Credentials.HTTPTokens {
		if token.Ref == name {
			return append([]string(nil), token.ScopeLabels...)
		}
	}
	return nil
}

func hostMatchesPattern(host, pattern string) bool {
	pattern = strings.ToLower(pattern)
	host = strings.ToLower(host)
	if pattern == host {
		return true
	}
	if strings.HasPrefix(pattern, "*.") {
		suffix := strings.TrimPrefix(pattern, "*")
		return strings.HasSuffix(host, suffix) || host == strings.TrimPrefix(suffix, ".")
	}
	ok, err := filepath.Match(pattern, host)
	return err == nil && ok
}

func headerMatchesPattern(header, pattern string) bool {
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	header = strings.ToLower(strings.TrimSpace(header))
	if pattern == header {
		return true
	}
	if strings.HasSuffix(pattern, "*") {
		prefix := strings.TrimSuffix(pattern, "*")
		return strings.HasPrefix(header, prefix)
	}
	return strings.Contains(header, pattern)
}
