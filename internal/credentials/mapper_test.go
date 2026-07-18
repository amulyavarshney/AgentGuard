package credentials_test

import (
	"testing"

	"github.com/amulyavarshney/agentguard/internal/config"
	"github.com/amulyavarshney/agentguard/internal/credentials"
)

func TestResolveAWSScopeAndEnvironment(t *testing.T) {
	t.Parallel()
	mapper := credentials.NewConfigMapper(config.Config{
		Credentials: config.CredentialsConfig{
			AWSProfiles: []config.AWSCredentialProfile{
				{
					Profile:     "prod-oncall",
					Environment: "production",
					ScopeLabels: []string{"iam:write", "rds:admin"},
				},
			},
		},
	})
	ref, scope, env := mapper.ResolveAWS("prod-oncall")
	if ref != "aws:prod-oncall" {
		t.Fatalf("ref = %q", ref)
	}
	if env != "production" {
		t.Fatalf("env = %q", env)
	}
	if len(scope) != 2 || scope[0] != "iam:write" {
		t.Fatalf("scope = %v", scope)
	}
}

func TestResolvePostgresHostPattern(t *testing.T) {
	t.Parallel()
	mapper := credentials.NewConfigMapper(config.Config{
		Credentials: config.CredentialsConfig{
			Postgres: []config.PostgresCredential{
				{
					ConnRef:     "production-db",
					HostPattern: "*.prod.example.com",
					Environment: "production",
					ScopeLabels: []string{"db:drop"},
				},
			},
		},
	})
	ref, scope, env := mapper.ResolvePostgres("db.prod.example.com", "app", "admin")
	if ref != "pg:production-db" {
		t.Fatalf("ref = %q", ref)
	}
	if env != "production" {
		t.Fatalf("env = %q", env)
	}
	if len(scope) != 1 || scope[0] != "db:drop" {
		t.Fatalf("scope = %v", scope)
	}
}

func TestResolveHTTPAuthBearer(t *testing.T) {
	t.Parallel()
	mapper := credentials.NewConfigMapper(config.Config{
		Credentials: config.CredentialsConfig{
			HTTPTokens: []config.HTTPTokenCredential{
				{
					Ref:           "github-api",
					HeaderPattern: "bearer ghp_",
					ScopeLabels:   []string{"github:repo"},
				},
			},
		},
	})
	ref, scope := mapper.ResolveHTTPAuth("Bearer ghp_abc123token")
	if ref != "http:github-api" {
		t.Fatalf("ref = %q", ref)
	}
	if len(scope) != 1 || scope[0] != "github:repo" {
		t.Fatalf("scope = %v", scope)
	}
}

func TestResolveOpaqueBearerWithoutConfig(t *testing.T) {
	t.Parallel()
	mapper := credentials.NewConfigMapper(config.Config{})
	ref, scope := mapper.ResolveHTTPAuth("Bearer unknown-token")
	if ref != "http:bearer-opaque" {
		t.Fatalf("ref = %q", ref)
	}
	if scope != nil {
		t.Fatalf("scope = %v, want nil", scope)
	}
}
