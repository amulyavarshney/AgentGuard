package adapters

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/amulyavarshney/agentguard/internal/model"
	"github.com/google/uuid"
)

const largeEgressHint = 10 * 1024 * 1024 // 10 MiB — matches destructive-pack large-egress rule

// HTTPAdapter classifies proxied HTTP requests.
type HTTPAdapter struct{}

// NewHTTPAdapter creates an HTTP request classifier.
func NewHTTPAdapter() *HTTPAdapter {
	return &HTTPAdapter{}
}

// Classify implements Adapter for HTTP proxy proposals.
func (a *HTTPAdapter) Classify(_ context.Context, raw map[string]any) (model.ActionProposal, error) {
	method, _ := raw["method"].(string)
	host, _ := raw["host"].(string)
	path, _ := raw["path"].(string)
	scheme, _ := raw["scheme"].(string)
	sessionID, _ := raw["session_id"].(string)
	environment, _ := raw["environment"].(string)
	task, _ := raw["task"].(string)
	egressBytes := int64FromAny(raw["egress_bytes"])
	connect, _ := raw["connect"].(bool)

	headers := headerMap(raw["headers"])
	auth := headers["authorization"]

	action := classifyHTTPAction(method, host, path, headers, egressBytes, connect)
	resources := []string{formatHTTPResource(scheme, host, path)}

	command := fmt.Sprintf("%s %s%s", method, host, path)
	if connect {
		command = fmt.Sprintf("CONNECT %s", host)
	}

	proposal := model.ActionProposal{
		ID:                uuid.NewString(),
		SessionID:         sessionID,
		Timestamp:         time.Now().UTC(),
		IntentSummary:     task,
		ActionType:        "http",
		Command:           command,
		Environment:       environment,
		AffectedResources: resources,
		RawRequest: map[string]any{
			"method":       method,
			"host":         host,
			"path":         path,
			"scheme":       scheme,
			"connect":      connect,
			"egress_bytes": egressBytes,
			"headers":      headers,
			"action":       action,
		},
	}

	if auth != "" {
		proposal.RawRequest["authorization"] = redactAuth(auth)
	}
	if egressBytes >= largeEgressHint {
		proposal.RawRequest["large_egress"] = true
	}

	return proposal, nil
}

func classifyHTTPAction(method, host, path string, headers map[string]string, egressBytes int64, connect bool) string {
	if connect {
		return "https_tunnel"
	}
	lowerPath := strings.ToLower(path)
	lowerHost := strings.ToLower(host)

	if strings.Contains(lowerPath, "/secrets") ||
		strings.Contains(lowerPath, "secret") ||
		strings.Contains(lowerHost, "secretsmanager") {
		return "secrets_get"
	}
	if strings.Contains(lowerPath, "export") && strings.Contains(lowerPath, "credential") {
		return "credential_export"
	}
	if auth := headers["authorization"]; auth != "" {
		if strings.Contains(strings.ToLower(auth), "export") {
			return "credential_export"
		}
	}
	if egressBytes >= largeEgressHint {
		return "large_egress"
	}
	if method == "DELETE" || method == "PUT" || method == "POST" {
		return strings.ToLower(method)
	}
	return "request"
}

func formatHTTPResource(scheme, host, path string) string {
	if scheme == "" {
		scheme = "http"
	}
	if path == "" {
		path = "/"
	}
	return scheme + "://" + host + path
}

func headerMap(v any) map[string]string {
	out := map[string]string{}
	switch t := v.(type) {
	case map[string]string:
		for k, val := range t {
			out[strings.ToLower(k)] = val
		}
	case map[string]any:
		for k, val := range t {
			if s, ok := val.(string); ok {
				out[strings.ToLower(k)] = s
			}
		}
	}
	return out
}

func redactAuth(auth string) string {
	parts := strings.Fields(auth)
	if len(parts) >= 2 && strings.EqualFold(parts[0], "Bearer") {
		token := parts[1]
		if len(token) <= 8 {
			return "Bearer [redacted]"
		}
		return "Bearer " + token[:4] + "…" + token[len(token)-4:]
	}
	return "[redacted]"
}

func int64FromAny(v any) int64 {
	switch t := v.(type) {
	case int:
		return int64(t)
	case int64:
		return t
	case float64:
		return int64(t)
	default:
		return 0
	}
}

// ParseHTTPHost normalizes host from a URL or Host header value.
func ParseHTTPHost(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if strings.Contains(raw, "://") {
		if u, err := url.Parse(raw); err == nil {
			return u.Host
		}
	}
	return raw
}
