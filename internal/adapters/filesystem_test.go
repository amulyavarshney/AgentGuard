package adapters_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/amulyavarshney/agentguard/internal/adapters"
)

func TestFilesystemAdapterClassifyDeleteOutsideAllowlist(t *testing.T) {
	t.Parallel()

	cwd := t.TempDir()
	adapter := adapters.NewFilesystemAdapter([]string{cwd})

	proposal, err := adapter.Classify(context.Background(), map[string]any{
		"tool":        "rm",
		"argv":        []string{"-rf", "/etc/hosts"},
		"cwd":         cwd,
		"session_id":  "sess-1",
		"environment": "staging",
		"task":        "cleanup temp files",
	})
	if err != nil {
		t.Fatalf("classify: %v", err)
	}

	if proposal.ActionType != "filesystem" {
		t.Fatalf("action_type = %q, want filesystem", proposal.ActionType)
	}
	if proposal.Command != "rm -rf /etc/hosts" {
		t.Fatalf("command = %q", proposal.Command)
	}
	if proposal.RawRequest["fs_action"] != "delete" {
		t.Fatalf("fs_action = %v", proposal.RawRequest["fs_action"])
	}
	if proposal.RawRequest["recursive"] != true {
		t.Fatalf("recursive = %v", proposal.RawRequest["recursive"])
	}
	if proposal.RawRequest["outside_allowlist"] != true {
		t.Fatalf("outside_allowlist = %v", proposal.RawRequest["outside_allowlist"])
	}
	if proposal.RawRequest["action"] != "rm_recursive" {
		t.Fatalf("action = %v", proposal.RawRequest["action"])
	}
}

func TestFilesystemAdapterClassifyDeleteInsideAllowlist(t *testing.T) {
	t.Parallel()

	cwd := t.TempDir()
	target := filepath.Join(cwd, "scratch.txt")
	adapter := adapters.NewFilesystemAdapter([]string{cwd})

	proposal, err := adapter.Classify(context.Background(), map[string]any{
		"tool": "rm",
		"argv": []string{target},
		"cwd":  cwd,
	})
	if err != nil {
		t.Fatalf("classify: %v", err)
	}

	if proposal.RawRequest["outside_allowlist"] != false {
		t.Fatalf("outside_allowlist = %v, want false", proposal.RawRequest["outside_allowlist"])
	}
}

func TestFilesystemAdapterDetectsBackupPaths(t *testing.T) {
	t.Parallel()

	adapter := adapters.NewFilesystemAdapter(nil)
	proposal, err := adapter.Classify(context.Background(), map[string]any{
		"tool": "rm",
		"argv": []string{"/var/data/nightly-backup.sql"},
		"cwd":  "/tmp",
	})
	if err != nil {
		t.Fatalf("classify: %v", err)
	}
	if proposal.RawRequest["touches_backup"] != true {
		t.Fatalf("touches_backup = %v", proposal.RawRequest["touches_backup"])
	}
}

func TestFilesystemAdapterClassifyChmod(t *testing.T) {
	t.Parallel()

	cwd := t.TempDir()
	adapter := adapters.NewFilesystemAdapter([]string{cwd})
	proposal, err := adapter.Classify(context.Background(), map[string]any{
		"tool": "chmod",
		"argv": []string{"755", filepath.Join(cwd, "run.sh")},
		"cwd":  cwd,
	})
	if err != nil {
		t.Fatalf("classify: %v", err)
	}
	if proposal.RawRequest["fs_action"] != "chmod" {
		t.Fatalf("fs_action = %v", proposal.RawRequest["fs_action"])
	}
}

func TestShellAdapterNestedDestructiveCommand(t *testing.T) {
	t.Parallel()

	fs := adapters.NewFilesystemAdapter(nil)
	shell := adapters.NewShellAdapter(fs)

	proposal, err := shell.Classify(context.Background(), map[string]any{
		"tool":        "bash",
		"argv":        []string{"-c", "rm -rf /important/data"},
		"cwd":         "/tmp",
		"session_id":  "sess-2",
		"environment": "production",
		"task":        "fix typo",
	})
	if err != nil {
		t.Fatalf("classify: %v", err)
	}

	if proposal.ActionType != "shell" {
		t.Fatalf("action_type = %q, want shell", proposal.ActionType)
	}
	if proposal.RawRequest["nested_tool"] != "rm" {
		t.Fatalf("nested_tool = %v", proposal.RawRequest["nested_tool"])
	}
	if proposal.RawRequest["outside_allowlist"] != true {
		t.Fatalf("outside_allowlist = %v", proposal.RawRequest["outside_allowlist"])
	}
}
