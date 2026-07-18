package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// LoadDocument reads and parses a policy YAML file.
func LoadDocument(path string) (Document, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Document{}, fmt.Errorf("read policy: %w", err)
	}
	var doc Document
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return Document{}, fmt.Errorf("parse policy: %w", err)
	}
	return doc, nil
}

// LoadFromDir loads all YAML files in dir and subdirs default/ and learned/.
// skipPackIDs maps policy file basenames (without extension) to skip when disabled.
func LoadFromDir(policyDir string, skipPackIDs map[string]bool) ([]Rule, error) {
	if policyDir == "" {
		return nil, fmt.Errorf("policy directory is empty")
	}
	var paths []string
	for _, sub := range []string{"default", "learned", "."} {
		dir := filepath.Join(policyDir, sub)
		entries, err := os.ReadDir(dir)
		if err != nil {
			if os.IsNotExist(err) && sub != "." {
				continue
			}
			if os.IsNotExist(err) && sub == "." {
				continue
			}
			return nil, fmt.Errorf("read policy dir %s: %w", dir, err)
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			name := e.Name()
			if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
				continue
			}
			packID := strings.TrimSuffix(strings.TrimSuffix(name, ".yaml"), ".yml")
			if skipPackIDs != nil && skipPackIDs[packID] {
				continue
			}
			paths = append(paths, filepath.Join(dir, name))
		}
		if sub == "." {
			break
		}
	}
	if len(paths) == 0 {
		return nil, fmt.Errorf("no policy YAML files found under %s", policyDir)
	}

	seen := make(map[string]string)
	var rules []Rule
	for _, path := range paths {
		doc, err := LoadDocument(path)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		if err := ValidateDocument(doc); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		for _, rule := range doc.Rules {
			if prev, dup := seen[rule.ID]; dup {
				return nil, fmt.Errorf("duplicate rule id %q in %s and %s", rule.ID, prev, path)
			}
			seen[rule.ID] = path
			rules = append(rules, rule)
		}
	}
	return rules, nil
}

// ValidateFile loads and validates a policy file path.
func ValidateFile(path string) error {
	doc, err := LoadDocument(path)
	if err != nil {
		return err
	}
	return ValidateDocument(doc)
}
