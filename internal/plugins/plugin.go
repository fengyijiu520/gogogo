package plugins

import "context"

// Plugin is the interface all scan plugins must implement.
type Plugin interface {
	// Name returns the plugin's display name.
	Name() string
	// Execute scans the given path and returns a list of findings.
	Execute(ctx context.Context, path string) ([]Finding, error)
}

// Finding represents a single issue found during scanning.
type Finding struct {
	PluginName  string
	RuleID      string
	Severity    string // 高风险 | 中风险 | 低风险
	Title       string
	Description string
	Location    string
	CodeSnippet string `json:"code_snippet,omitempty"` // 新增字段
}