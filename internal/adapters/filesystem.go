package adapters

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/amulyavarshney/agentguard/internal/model"
	"github.com/google/uuid"
)

// FSActionKind classifies a filesystem operation.
type FSActionKind string

const (
	FSActionDelete    FSActionKind = "delete"
	FSActionOverwrite FSActionKind = "overwrite"
	FSActionChmod     FSActionKind = "chmod"
	FSActionMove      FSActionKind = "move"
	FSActionUnknown   FSActionKind = "unknown"
)

// FilesystemAdapter classifies gated filesystem tool invocations.
type FilesystemAdapter struct {
	AllowlistRoots []string
}

// NewFilesystemAdapter creates a classifier with optional path allowlist roots.
func NewFilesystemAdapter(allowlistRoots []string) *FilesystemAdapter {
	return &FilesystemAdapter{AllowlistRoots: allowlistRoots}
}

// Classify implements Adapter for filesystem tools (rm, mv, chmod).
func (a *FilesystemAdapter) Classify(_ context.Context, raw map[string]any) (model.ActionProposal, error) {
	tool, _ := raw["tool"].(string)
	argv := stringSlice(raw["argv"])
	cwd, _ := raw["cwd"].(string)
	if cwd == "" {
		cwd, _ = os.Getwd()
	}
	sessionID, _ := raw["session_id"].(string)
	environment, _ := raw["environment"].(string)
	task, _ := raw["task"].(string)

	kind, paths, recursive := classifyTool(tool, argv)
	allowlist := a.effectiveAllowlist(cwd)
	outside := pathsOutsideAllowlist(paths, allowlist)

	proposal := model.ActionProposal{
		ID:            uuid.NewString(),
		SessionID:     sessionID,
		Timestamp:     time.Now().UTC(),
		IntentSummary: task,
		ActionType:    "filesystem",
		Command:       formatCommand(tool, argv),
		Environment:   environment,
		RawRequest: map[string]any{
			"tool":              tool,
			"argv":              argv,
			"cwd":               cwd,
			"fs_action":         string(kind),
			"paths":             paths,
			"recursive":         recursive,
			"outside_allowlist": outside,
			"allowlist_roots":   allowlist,
		},
		AffectedResources: paths,
	}

	if recursive && kind == FSActionDelete {
		proposal.RawRequest["action"] = "rm_recursive"
		proposal.EstimatedBlastRadius = len(paths)
		if proposal.EstimatedBlastRadius == 0 {
			proposal.EstimatedBlastRadius = 1
		}
	}

	for _, p := range paths {
		lower := strings.ToLower(p)
		if strings.Contains(lower, "backup") || strings.Contains(lower, "snapshot") {
			proposal.RawRequest["touches_backup"] = true
			break
		}
	}

	return proposal, nil
}

func classifyTool(tool string, argv []string) (FSActionKind, []string, bool) {
	switch filepath.Base(tool) {
	case "rm":
		return classifyRM(argv)
	case "mv":
		return classifyMV(argv)
	case "chmod", "chown":
		return classifyChmod(tool, argv)
	default:
		return FSActionUnknown, extractPaths(argv), false
	}
}

func classifyRM(argv []string) (FSActionKind, []string, bool) {
	recursive := false
	var paths []string
	for _, arg := range argv {
		if arg == "--" {
			continue
		}
		if strings.HasPrefix(arg, "-") {
			if strings.Contains(arg, "r") || strings.Contains(arg, "R") {
				recursive = true
			}
			continue
		}
		paths = append(paths, arg)
	}
	return FSActionDelete, paths, recursive
}

func classifyMV(argv []string) (FSActionKind, []string, bool) {
	var paths []string
	for _, arg := range argv {
		if arg == "--" || strings.HasPrefix(arg, "-") {
			continue
		}
		paths = append(paths, arg)
	}
	kind := FSActionMove
	if len(paths) >= 2 {
		dest := paths[len(paths)-1]
		if info, err := os.Stat(dest); err == nil && !info.IsDir() {
			kind = FSActionOverwrite
		}
	}
	return kind, paths, false
}

func classifyChmod(tool string, argv []string) (FSActionKind, []string, bool) {
	var paths []string
	modeSeen := false
	for _, arg := range argv {
		if arg == "--" {
			continue
		}
		if strings.HasPrefix(arg, "-") {
			continue
		}
		if tool == "chmod" && !modeSeen {
			modeSeen = true
			continue
		}
		paths = append(paths, arg)
	}
	return FSActionChmod, paths, false
}

func extractPaths(argv []string) []string {
	var paths []string
	for _, arg := range argv {
		if arg == "--" || strings.HasPrefix(arg, "-") {
			continue
		}
		paths = append(paths, arg)
	}
	return paths
}

func formatCommand(tool string, argv []string) string {
	if len(argv) == 0 {
		return tool
	}
	return fmt.Sprintf("%s %s", tool, strings.Join(argv, " "))
}

func (a *FilesystemAdapter) effectiveAllowlist(cwd string) []string {
	roots := append([]string(nil), a.AllowlistRoots...)
	if cwd != "" {
		roots = append(roots, cwd)
	}
	if tmp := os.TempDir(); tmp != "" {
		roots = append(roots, tmp)
	}
	roots = append(roots, "/tmp", "/var/tmp")
	return dedupeAbsPaths(roots)
}

func dedupeAbsPaths(paths []string) []string {
	seen := make(map[string]struct{}, len(paths))
	var out []string
	for _, p := range paths {
		if p == "" {
			continue
		}
		abs, err := filepath.Abs(p)
		if err != nil {
			abs = p
		}
		abs = filepath.Clean(abs)
		if _, ok := seen[abs]; ok {
			continue
		}
		seen[abs] = struct{}{}
		out = append(out, abs)
	}
	return out
}

// pathsOutsideAllowlist reports whether any path resolves outside the allowlist roots.
func pathsOutsideAllowlist(paths, allowlist []string) bool {
	if len(allowlist) == 0 {
		return len(paths) > 0
	}
	for _, p := range paths {
		if pathOutsideAllowlist(p, allowlist) {
			return true
		}
	}
	return false
}

func pathOutsideAllowlist(p string, allowlist []string) bool {
	if p == "" {
		return false
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		abs = p
	}
	abs = filepath.Clean(abs)
	for _, root := range allowlist {
		root = filepath.Clean(root)
		if abs == root || strings.HasPrefix(abs, root+string(os.PathSeparator)) {
			return false
		}
	}
	return true
}

func stringSlice(v any) []string {
	switch t := v.(type) {
	case []string:
		return append([]string(nil), t...)
	case []any:
		out := make([]string, 0, len(t))
		for _, item := range t {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}
