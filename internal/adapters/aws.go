package adapters

import (
	"context"
	"strings"
	"time"

	"github.com/amulyavarshney/agentguard/internal/model"
	"github.com/google/uuid"
)

// AWSAdapter classifies AWS CLI invocations.
type AWSAdapter struct{}

// NewAWSAdapter creates an AWS CLI classifier.
func NewAWSAdapter() *AWSAdapter {
	return &AWSAdapter{}
}

// Classify implements Adapter for aws shim proposals.
func (a *AWSAdapter) Classify(_ context.Context, raw map[string]any) (model.ActionProposal, error) {
	tool, _ := raw["tool"].(string)
	argv := stringSlice(raw["argv"])
	sessionID, _ := raw["session_id"].(string)
	environment, _ := raw["environment"].(string)
	task, _ := raw["task"].(string)
	cwd, _ := raw["cwd"].(string)

	profile, region, service, operation, positional := parseAWSArgv(argv)
	action, resources := classifyAWS(service, operation, positional, argv)

	proposal := model.ActionProposal{
		ID:                uuid.NewString(),
		SessionID:         sessionID,
		Timestamp:         time.Now().UTC(),
		IntentSummary:     task,
		ActionType:        "aws",
		Command:           formatCommand(tool, argv),
		Environment:       environment,
		AffectedResources: resources,
		RawRequest: map[string]any{
			"tool":      tool,
			"argv":      argv,
			"cwd":       cwd,
			"profile":   profile,
			"region":    region,
			"service":   service,
			"operation": operation,
			"action":    action,
		},
	}
	if action != "" && action != "unknown" {
		proposal.RawRequest["aws_action"] = action
	}
	return proposal, nil
}

func parseAWSArgv(argv []string) (profile, region, service, operation string, positional []string) {
	profile = "default"
	i := 0
	for i < len(argv) {
		arg := argv[i]
		switch {
		case arg == "--profile" || arg == "-p":
			if i+1 < len(argv) {
				profile = argv[i+1]
				i += 2
				continue
			}
		case strings.HasPrefix(arg, "--profile="):
			profile = strings.TrimPrefix(arg, "--profile=")
		case arg == "--region" || arg == "-r":
			if i+1 < len(argv) {
				region = argv[i+1]
				i += 2
				continue
			}
		case strings.HasPrefix(arg, "--region="):
			region = strings.TrimPrefix(arg, "--region=")
		case strings.HasPrefix(arg, "-"):
			// Skip unknown global flags with values.
			if i+1 < len(argv) && !strings.HasPrefix(argv[i+1], "-") && !strings.Contains(arg, "=") {
				i += 2
				continue
			}
			i++
			continue
		default:
			service = arg
			if i+1 < len(argv) {
				operation = argv[i+1]
			}
			if i+2 < len(argv) {
				positional = argv[i+2:]
			}
			return profile, region, service, operation, positional
		}
		i++
	}
	return profile, region, service, operation, positional
}

func classifyAWS(service, operation string, positional, argv []string) (action string, resources []string) {
	service = strings.ToLower(service)
	operation = strings.ToLower(operation)

	resources = extractAWSResources(argv, positional)

	switch service {
	case "iam":
		action = classifyIAM(operation)
	case "s3":
		action = classifyS3(operation, argv)
	case "s3api":
		action = classifyS3API(operation)
	case "rds":
		action = classifyRDS(operation)
	case "secretsmanager":
		action = classifySecretsManager(operation)
	case "cloudtrail":
		action = classifyCloudTrail(operation)
	case "budgets":
		action = classifyBudgets(operation)
	case "ce":
		action = classifyCE(operation)
	case "logs":
		action = classifyCloudWatchLogs(operation)
	default:
		action = service + "_" + strings.ReplaceAll(operation, "-", "_")
	}
	if action == "" {
		action = "unknown"
	}
	return action, resources
}

func classifyIAM(op string) string {
	switch op {
	case "create-user":
		return "iam_create_user"
	case "delete-user":
		return "iam_delete_user"
	case "attach-user-policy":
		return "iam_attach_policy"
	case "detach-user-policy":
		return "iam_detach_policy"
	case "delete-role":
		return "iam_delete_role"
	case "create-role":
		return "iam_create_role"
	case "put-role-policy":
		return "iam_put_role_policy"
	default:
		return "iam_" + strings.ReplaceAll(op, "-", "_")
	}
}

func classifyS3(op string, argv []string) string {
	switch op {
	case "rm", "rb":
		return "s3_delete"
	case "sync":
		// sync with --delete is destructive
		for _, a := range argv {
			if a == "--delete" {
				return "s3_delete"
			}
		}
	}
	return "s3_" + op
}

func classifyS3API(op string) string {
	switch op {
	case "delete-object", "delete-objects", "delete-bucket":
		return "s3_delete"
	default:
		return "s3_" + strings.ReplaceAll(op, "-", "_")
	}
}

func classifyRDS(op string) string {
	switch op {
	case "delete-db-instance":
		return "rds_delete_db_instance"
	case "delete-db-cluster":
		return "rds_delete_db_cluster"
	case "delete-db-snapshot":
		return "snapshot_delete"
	case "delete-db-cluster-snapshot":
		return "snapshot_delete"
	default:
		return "rds_" + strings.ReplaceAll(op, "-", "_")
	}
}

func classifySecretsManager(op string) string {
	switch op {
	case "get-secret-value":
		return "secrets_manager_get"
	case "rotate-secret":
		return "secret_rotation"
	case "put-secret-value":
		return "secrets_put"
	default:
		return "secrets_" + strings.ReplaceAll(op, "-", "_")
	}
}

func classifyCloudTrail(op string) string {
	switch op {
	case "stop-logging":
		return "cloudtrail_stop"
	case "delete-trail":
		return "disable_logging"
	default:
		return "cloudtrail_" + strings.ReplaceAll(op, "-", "_")
	}
}

func classifyBudgets(op string) string {
	switch op {
	case "delete-budget":
		return "budget_delete"
	case "modify-budget":
		return "budget_modify"
	default:
		return "budgets_" + strings.ReplaceAll(op, "-", "_")
	}
}

func classifyCE(op string) string {
	switch op {
	case "create-anomaly-monitor":
		return "ce_create_anomaly_monitor"
	default:
		return "ce_" + strings.ReplaceAll(op, "-", "_")
	}
}

func classifyCloudWatchLogs(op string) string {
	switch op {
	case "delete-log-group", "delete-log-stream", "delete-metric-filter", "delete-alarms":
		return "cloudwatch_delete_alarms"
	default:
		return "logs_" + strings.ReplaceAll(op, "-", "_")
	}
}

func extractAWSResources(argv, positional []string) []string {
	var resources []string
	for i := 0; i < len(argv); i++ {
		switch argv[i] {
		case "--db-instance-identifier", "--db-cluster-identifier", "--db-snapshot-identifier",
			"--bucket", "--key", "--secret-id", "--name", "--trail-name", "--budget-name",
			"--user-name", "--role-name", "--policy-arn":
			if i+1 < len(argv) {
				resources = append(resources, argv[i+1])
			}
		}
	}
	for _, p := range positional {
		if strings.HasPrefix(p, "s3://") || strings.HasPrefix(p, "arn:") {
			resources = append(resources, p)
		}
	}
	return resources
}
