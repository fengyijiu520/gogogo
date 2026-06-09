package plugins

import "context"

type PluginType string

const (
	PluginTypeDetector PluginType = "detector"
	PluginTypeSandbox  PluginType = "sandbox"
)

// Metadata describes a plugin in a standard, extensible way.
type Metadata struct {
	ID           string
	Name         string
	Version      string
	Description  string
	Type         PluginType
	Capabilities []string
	HotSwappable bool
}

// ExecuteRequest carries normalized inputs for plugin execution.
type ExecuteRequest struct {
	ScanPath string
	Options  map[string]string
}

// ExecuteResponse carries findings and optional runtime statistics.
type ExecuteResponse struct {
	Findings []Finding
	Stats    map[string]int
}

// Scanner is the unified plugin contract for detectors/sandbox adapters.
type Scanner interface {
	Metadata() Metadata
	Execute(ctx context.Context, req ExecuteRequest) (ExecuteResponse, error)
}

// Plugin is the interface all scan plugins must implement.
// Deprecated: use Scanner for all new plugins.
type Plugin interface {
	// Name returns the plugin's display name.
	Name() string
	// Execute scans the given path and returns a list of findings.
	Execute(ctx context.Context, path string) ([]Finding, error)
}

type legacyAdapter struct {
	meta   Metadata
	plugin Plugin
}

func (a *legacyAdapter) Metadata() Metadata {
	return a.meta
}

func (a *legacyAdapter) Execute(ctx context.Context, req ExecuteRequest) (ExecuteResponse, error) {
	findings, err := a.plugin.Execute(ctx, req.ScanPath)
	if err != nil {
		return ExecuteResponse{}, err
	}
	return ExecuteResponse{Findings: findings}, nil
}

func AdaptLegacy(meta Metadata, p Plugin) Scanner {
	return &legacyAdapter{meta: meta, plugin: p}
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
