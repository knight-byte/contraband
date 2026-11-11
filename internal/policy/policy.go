package policy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"
)

const FileName = ".contraband.yml"

const (
	Allow = "allow"
	Warn  = "warn"
)

type Rule struct {
	Domain  string `yaml:"domain"`
	Package string `yaml:"package,omitempty"`
}

// Policy is a snapshot taken at session start; later edits to the file do not
// change it.
type Policy struct {
	Version int    `yaml:"version"`
	Allow   []Rule `yaml:"allow"`
	Hash    string `yaml:"-"`
}

func Hash(content []byte) string {
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}

func Parse(content []byte) (*Policy, error) {
	parsed := &Policy{Hash: Hash(content)}
	if len(content) == 0 {
		return parsed, nil
	}
	decoder := yaml.NewDecoder(bytes.NewReader(content))
	decoder.KnownFields(true)
	if err := decoder.Decode(parsed); err != nil {
		return nil, fmt.Errorf("parse %s: %w", FileName, err)
	}
	if parsed.Version != 1 {
		return nil, fmt.Errorf("parse %s: unsupported version %d", FileName, parsed.Version)
	}
	for index, rule := range parsed.Allow {
		if rule.Domain == "" {
			return nil, fmt.Errorf("parse %s: allow[%d]: domain is required", FileName, index)
		}
		if _, err := path.Match(rule.Domain, ""); err != nil {
			return nil, fmt.Errorf("parse %s: allow[%d]: %w", FileName, index, err)
		}
	}
	return parsed, nil
}

// Check matches a destination host name or IP address. It is monitor-only:
// anything not allowed is a warning, never a block. Without rules there is
// nothing to check against and the verdict is empty.
func (policy *Policy) Check(pkg, domain string) string {
	if policy == nil || len(policy.Allow) == 0 {
		return ""
	}
	domain = strings.TrimSuffix(strings.ToLower(domain), ".")
	for _, rule := range policy.Allow {
		if rule.Package != "" && rule.Package != pkg {
			continue
		}
		if matched, _ := path.Match(strings.ToLower(rule.Domain), domain); matched {
			return Allow
		}
	}
	return Warn
}

const emptyPolicy = "# Destinations this project is expected to reach. Changes take effect\n# only after `contraband approve`.\nversion: 1\nallow: []\n"

// AddRule appends rule to a policy file's allow list, keeping the file's
// comments and layout. It returns the content unchanged when the rule exists.
func AddRule(content []byte, rule Rule) ([]byte, error) {
	if len(bytes.TrimSpace(content)) == 0 {
		content = []byte(emptyPolicy)
	}
	existing, err := Parse(content)
	if err != nil {
		return nil, err
	}
	for _, current := range existing.Allow {
		if current == rule {
			return content, nil
		}
	}
	var root yaml.Node
	if err := yaml.Unmarshal(content, &root); err != nil {
		return nil, fmt.Errorf("parse %s: %w", FileName, err)
	}
	mapping := root.Content[0]
	var allow *yaml.Node
	for index := 0; index+1 < len(mapping.Content); index += 2 {
		if mapping.Content[index].Value == "allow" {
			allow = mapping.Content[index+1]
		}
	}
	if allow == nil {
		allow = &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
		mapping.Content = append(mapping.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "allow"}, allow)
	}
	var entry yaml.Node
	if err := entry.Encode(rule); err != nil {
		return nil, fmt.Errorf("encode rule: %w", err)
	}
	allow.Style = 0
	allow.Content = append(allow.Content, &entry)

	var out bytes.Buffer
	encoder := yaml.NewEncoder(&out)
	encoder.SetIndent(2)
	if err := encoder.Encode(&root); err != nil {
		return nil, fmt.Errorf("encode %s: %w", FileName, err)
	}
	return out.Bytes(), nil
}

// Diff lists rules added and removed going from before to after.
func Diff(before, after *Policy) (added, removed []Rule) {
	for _, rule := range after.Allow {
		if !slices.Contains(before.Allow, rule) {
			added = append(added, rule)
		}
	}
	for _, rule := range before.Allow {
		if !slices.Contains(after.Allow, rule) {
			removed = append(removed, rule)
		}
	}
	return added, removed
}

// RemoveRule deletes rule from a policy file's allow list, keeping comments
// and layout. It reports whether the rule was present.
func RemoveRule(content []byte, rule Rule) ([]byte, bool, error) {
	if _, err := Parse(content); err != nil {
		return nil, false, err
	}
	var root yaml.Node
	if err := yaml.Unmarshal(content, &root); err != nil || len(root.Content) == 0 {
		return content, false, nil
	}
	mapping := root.Content[0]
	removed := false
	for index := 0; index+1 < len(mapping.Content); index += 2 {
		if mapping.Content[index].Value != "allow" {
			continue
		}
		allow := mapping.Content[index+1]
		kept := allow.Content[:0]
		for _, item := range allow.Content {
			var current Rule
			if item.Decode(&current) == nil && current == rule {
				removed = true
				continue
			}
			kept = append(kept, item)
		}
		allow.Content = kept
	}
	if !removed {
		return content, false, nil
	}
	var out bytes.Buffer
	encoder := yaml.NewEncoder(&out)
	encoder.SetIndent(2)
	if err := encoder.Encode(&root); err != nil {
		return nil, false, fmt.Errorf("encode %s: %w", FileName, err)
	}
	return out.Bytes(), true, nil
}
