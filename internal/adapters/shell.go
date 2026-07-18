package adapters

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/amulyavarshney/agentguard/internal/model"
	"github.com/google/uuid"
)

// ShellAdapter classifies shell invocations routed through sh/bash shims.
type ShellAdapter struct {
	Filesystem *FilesystemAdapter
}

// NewShellAdapter creates a shell classifier with optional filesystem delegate.
func NewShellAdapter(fs *FilesystemAdapter) *ShellAdapter {
	return &ShellAdapter{Filesystem: fs}
}

// Classify implements Adapter for shell tool invocations.
func (a *ShellAdapter) Classify(ctx context.Context, raw map[string]any) (model.ActionProposal, error) {
	tool, _ := raw["tool"].(string)
	argv := stringSlice(raw["argv"])
	sessionID, _ := raw["session_id"].(string)
	environment, _ := raw["environment"].(string)
	task, _ := raw["task"].(string)
	cwd, _ := raw["cwd"].(string)

	// Nested destructive command via sh -c / bash -c
	if cmd, nestedTool, nestedArgv, ok := extractNestedCommand(tool, argv); ok && isGatedTool(nestedTool) {
		nestedRaw := map[string]any{
			"tool":        nestedTool,
			"argv":        nestedArgv,
			"cwd":         cwd,
			"session_id":  sessionID,
			"environment": environment,
			"task":        task,
		}
		if a.Filesystem != nil {
			proposal, err := a.Filesystem.Classify(ctx, nestedRaw)
			if err != nil {
				return model.ActionProposal{}, err
			}
			proposal.ActionType = "shell"
			proposal.Command = cmd
			proposal.RawRequest["shell"] = tool
			proposal.RawRequest["nested_tool"] = nestedTool
			return proposal, nil
		}
	}

	return model.ActionProposal{
		ID:            uuid.NewString(),
		SessionID:     sessionID,
		Timestamp:     time.Now().UTC(),
		IntentSummary: task,
		ActionType:    "shell",
		Command:       formatCommand(tool, argv),
		Environment:   environment,
		RawRequest: map[string]any{
			"tool": tool,
			"argv": argv,
			"cwd":  cwd,
		},
	}, nil
}

func extractNestedCommand(tool string, argv []string) (fullCmd, nestedTool string, nestedArgv []string, ok bool) {
	base := filepath.Base(tool)
	if base != "sh" && base != "bash" {
		return "", "", nil, false
	}
	for i, arg := range argv {
		if arg == "-c" && i+1 < len(argv) {
			script := argv[i+1]
			fullCmd = fmt.Sprintf("%s -c %q", tool, script)
			fields := strings.Fields(script)
			if len(fields) == 0 {
				return fullCmd, "", nil, false
			}
			return fullCmd, fields[0], fields[1:], true
		}
	}
	return "", "", nil, false
}

func isGatedTool(tool string) bool {
	switch filepath.Base(tool) {
	case "rm", "mv", "chmod", "chown":
		return true
	default:
		return false
	}
}
