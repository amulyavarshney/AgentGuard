package intent

import (
	"regexp"
	"strings"

	"github.com/amulyavarshney/agentguard/internal/model"
)

// HeuristicComparator compares session task instructions to proposed actions
// using deterministic keyword and scope heuristics (no LLM).
type HeuristicComparator struct{}

// NewHeuristicComparator returns the default intent comparator.
func NewHeuristicComparator() HeuristicComparator {
	return HeuristicComparator{}
}

// Compare implements Comparator.
func (HeuristicComparator) Compare(task string, proposal model.ActionProposal) (Result, error) {
	task = strings.TrimSpace(task)
	if task == "" {
		return Result{Aligned: true, Verdict: model.PolicyAllow}, nil
	}

	var reasons []string
	strictest := model.PolicyAllow

	taskEnvs := detectEnvironments(task)
	actionEnvs := detectActionEnvironments(proposal)
	if len(taskEnvs) > 0 && len(actionEnvs) > 0 && !environmentsOverlap(taskEnvs, actionEnvs) {
		reasons = append(reasons, "environment mismatch: task targets "+joinEnvironments(taskEnvs)+", action targets "+joinEnvironments(actionEnvs))
		strictest = strictestDecision(strictest, model.PolicyPauseAndEscalate)
	}

	if taskLooksNonDestructive(task) && actionLooksDestructive(proposal) {
		reasons = append(reasons, "destructive action conflicts with non-destructive task instruction")
		strictest = strictestDecision(strictest, model.PolicyBlock)
	}

	taskResources := extractScopedResources(task)
	actionResources := collectActionResources(proposal)
	if len(taskResources) > 0 && len(actionResources) > 0 && !resourcesOverlap(taskResources, actionResources) {
		reasons = append(reasons, "action targets resources outside declared task scope: "+strings.Join(actionResources, ", "))
		strictest = strictestDecision(strictest, model.PolicyRequireApproval)
	}

	// Production action while task explicitly scopes to non-production is a hard block when destructive.
	if environmentsContains(actionEnvs, envProduction) &&
		environmentsContains(taskEnvs, envStaging, envDev, envTest) &&
		!environmentsContains(taskEnvs, envProduction) &&
		actionLooksDestructive(proposal) {
		reasons = append(reasons, "destructive production action while task is scoped to non-production")
		strictest = strictestDecision(strictest, model.PolicyBlock)
	}

	if len(reasons) == 0 {
		return Result{Aligned: true, Verdict: model.PolicyAllow}, nil
	}
	return Result{
		Aligned: false,
		Reasons: reasons,
		Verdict: strictest,
	}, nil
}

type environmentKind string

const (
	envStaging    environmentKind = "staging"
	envProduction environmentKind = "production"
	envDev        environmentKind = "development"
	envTest       environmentKind = "test"
)

var (
	envPatterns = map[environmentKind][]*regexp.Regexp{
		envStaging: {
			regexp.MustCompile(`(?i)\bstaging\b`),
			regexp.MustCompile(`(?i)\bstage\b`),
			regexp.MustCompile(`(?i)\bstg\b`),
			regexp.MustCompile(`(?i)\bstg[-_]`),
			regexp.MustCompile(`(?i)[-_]stg\b`),
		},
		envProduction: {
			regexp.MustCompile(`(?i)\bproduction\b`),
			regexp.MustCompile(`(?i)\bprod\b`),
			regexp.MustCompile(`(?i)\bprd\b`),
			regexp.MustCompile(`(?i)\bprod[-_]`),
			regexp.MustCompile(`(?i)[-_]prod\b`),
		},
		envDev: {
			regexp.MustCompile(`(?i)\bdevelopment\b`),
			regexp.MustCompile(`(?i)\bdev\b`),
			regexp.MustCompile(`(?i)\bdev[-_]`),
			regexp.MustCompile(`(?i)[-_]dev\b`),
		},
		envTest: {
			regexp.MustCompile(`(?i)\btest\b`),
			regexp.MustCompile(`(?i)\bqa\b`),
			regexp.MustCompile(`(?i)\buat\b`),
		},
	}

	nonDestructiveTaskPattern = regexp.MustCompile(`(?i)\b(fix|debug|investigate|read|check|review|analyze|analyse|inspect|troubleshoot|diagnose|resolve|lookup|query|list|describe|show|explain|auth\s+error)\b`)
	destructiveActionPattern    = regexp.MustCompile(`(?i)\b(delete|drop|truncate|destroy|remove|rm\b|purge|wipe|terminate|kill|detach|revoke|disable|bulk_delete|delete-db-instance|delete-bucket|delete-table)\b`)
	resourceTokenPattern        = regexp.MustCompile(`(?i)\b([a-z][a-z0-9]*(?:[-_][a-z0-9]+)+)\b`)
)

func detectEnvironments(text string) map[environmentKind]struct{} {
	found := make(map[environmentKind]struct{})
	for kind, patterns := range envPatterns {
		for _, re := range patterns {
			if re.MatchString(text) {
				found[kind] = struct{}{}
				break
			}
		}
	}
	return found
}

func detectActionEnvironments(proposal model.ActionProposal) map[environmentKind]struct{} {
	var parts []string
	if proposal.Environment != "" {
		parts = append(parts, proposal.Environment)
	}
	parts = append(parts, proposal.Command)
	parts = append(parts, proposal.AffectedResources...)
	if proposal.RawRequest != nil {
		if action, ok := proposal.RawRequest["action"].(string); ok {
			parts = append(parts, action)
		}
	}
	return detectEnvironments(strings.Join(parts, " "))
}

func environmentsOverlap(a, b map[environmentKind]struct{}) bool {
	for k := range a {
		if _, ok := b[k]; ok {
			return true
		}
	}
	return false
}

func environmentsContains(set map[environmentKind]struct{}, kinds ...environmentKind) bool {
	for _, kind := range kinds {
		if _, ok := set[kind]; ok {
			return true
		}
	}
	return false
}

func joinEnvironments(set map[environmentKind]struct{}) string {
	order := []environmentKind{envStaging, envProduction, envDev, envTest}
	var names []string
	for _, kind := range order {
		if _, ok := set[kind]; ok {
			names = append(names, string(kind))
		}
	}
	if len(names) == 0 {
		return "unknown"
	}
	return strings.Join(names, ", ")
}

func taskLooksNonDestructive(task string) bool {
	if destructiveActionPattern.MatchString(task) {
		return false
	}
	return nonDestructiveTaskPattern.MatchString(task)
}

func actionLooksDestructive(proposal model.ActionProposal) bool {
	text := strings.Join(collectActionText(proposal), " ")
	if destructiveActionPattern.MatchString(text) {
		return true
	}
	if proposal.RawRequest != nil {
		switch proposal.RawRequest["fs_action"] {
		case "delete", "overwrite":
			return true
		}
		if action, ok := proposal.RawRequest["action"].(string); ok {
			switch action {
			case "rm_recursive", "drop", "truncate", "bulk_delete", "delete":
				return true
			}
		}
	}
	return false
}

func collectActionText(proposal model.ActionProposal) []string {
	parts := []string{proposal.Command, proposal.ActionType}
	parts = append(parts, proposal.AffectedResources...)
	return parts
}

func extractScopedResources(task string) map[string]struct{} {
	resources := make(map[string]struct{})
	for _, token := range resourceTokenPattern.FindAllString(task, -1) {
		lower := strings.ToLower(token)
		if isEnvironmentToken(lower) {
			continue
		}
		resources[normalizeResource(lower)] = struct{}{}
	}
	return resources
}

func collectActionResources(proposal model.ActionProposal) []string {
	seen := make(map[string]struct{})
	var out []string
	add := func(raw string) {
		for _, token := range resourceTokenPattern.FindAllString(raw, -1) {
			lower := strings.ToLower(token)
			if isEnvironmentToken(lower) {
				continue
			}
			key := normalizeResource(lower)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, key)
		}
	}
	add(proposal.Command)
	for _, r := range proposal.AffectedResources {
		add(r)
	}
	return out
}

func resourcesOverlap(taskResources map[string]struct{}, actionResources []string) bool {
	for _, actionRes := range actionResources {
		normalized := normalizeResource(actionRes)
		if _, ok := taskResources[normalized]; ok {
			return true
		}
		for taskRes := range taskResources {
			if strings.Contains(normalized, taskRes) || strings.Contains(taskRes, normalized) {
				return true
			}
		}
	}
	return false
}

func normalizeResource(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

func isEnvironmentToken(token string) bool {
	switch token {
	case "staging", "stage", "stg", "production", "prod", "prd", "development", "dev", "test", "qa", "uat":
		return true
	default:
		return false
	}
}

func strictestDecision(current, candidate model.PolicyDecision) model.PolicyDecision {
	if decisionStrictness(candidate) > decisionStrictness(current) {
		return candidate
	}
	return current
}

func decisionStrictness(d model.PolicyDecision) int {
	switch d {
	case model.PolicyBlock:
		return 4
	case model.PolicyPauseAndEscalate:
		return 3
	case model.PolicyRequireApproval:
		return 2
	case model.PolicyAllow:
		return 1
	default:
		return 0
	}
}
