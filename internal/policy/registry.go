package policy

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// PolicyEntry describes a loaded policy file for the control plane.
type PolicyEntry struct {
	ID       string `json:"id"`
	Source   string `json:"source"` // default | learned
	FilePath string `json:"file_path"`
	Enabled  bool   `json:"enabled"`
	RuleCount int   `json:"rule_count"`
}

// Registry tracks policy files and enable/disable state.
type Registry struct {
	policyDir string
	statePath string
	disabled  map[string]bool
}

// NewRegistry creates a policy registry rooted at policyDir.
// State is persisted under dataDir/policy-state.json.
func NewRegistry(policyDir, dataDir string) (*Registry, error) {
	r := &Registry{
		policyDir: policyDir,
		statePath: filepath.Join(dataDir, "policy-state.json"),
		disabled:  make(map[string]bool),
	}
	if err := r.loadState(); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *Registry) loadState() error {
	data, err := os.ReadFile(r.statePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read policy state: %w", err)
	}
	return json.Unmarshal(data, &r.disabled)
}

func (r *Registry) saveState() error {
	data, err := json.MarshalIndent(r.disabled, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal policy state: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(r.statePath), 0o755); err != nil {
		return fmt.Errorf("mkdir policy state dir: %w", err)
	}
	if err := os.WriteFile(r.statePath, data, 0o644); err != nil {
		return fmt.Errorf("write policy state: %w", err)
	}
	return nil
}

// List returns all known policy files from default/ and learned/ subdirs.
func (r *Registry) List() ([]PolicyEntry, error) {
	var entries []PolicyEntry
	for _, source := range []string{"default", "learned"} {
		dir := filepath.Join(r.policyDir, source)
		_ = os.MkdirAll(dir, 0o755)
		matches, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
		if err != nil {
			return nil, fmt.Errorf("glob policies: %w", err)
		}
		for _, path := range matches {
			doc, err := LoadDocument(path)
			if err != nil {
				continue
			}
			id := filepath.Base(path)
			id = strings.TrimSuffix(id, filepath.Ext(id))
			entries = append(entries, PolicyEntry{
				ID:        id,
				Source:    source,
				FilePath:  path,
				Enabled:   !r.disabled[id],
				RuleCount: len(doc.Rules),
			})
		}
	}
	if entries == nil {
		entries = []PolicyEntry{}
	}
	return entries, nil
}

// SetEnabled toggles a policy pack by ID.
func (r *Registry) SetEnabled(id string, enabled bool) error {
	if enabled {
		delete(r.disabled, id)
	} else {
		r.disabled[id] = true
	}
	return r.saveState()
}

// LoadEnabledRules returns rules from enabled policy packs only.
func (r *Registry) LoadEnabledRules() ([]Rule, error) {
	skip := make(map[string]bool)
	for id, disabled := range r.disabled {
		if disabled {
			skip[id] = true
		}
	}
	return LoadFromDir(r.policyDir, skip)
}

// Engine returns a policy engine respecting enable/disable state.
func (r *Registry) Engine() Engine {
	rules, err := r.LoadEnabledRules()
	if err != nil || len(rules) == 0 {
		return NewBaselineEngine(StubEngine{})
	}
	return NewBaselineEngine(NewDefaultEngine(rules))
}
