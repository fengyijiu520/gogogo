package models

// Finding represents a single security issue found by a plugin.
type Finding struct {
	PluginName  string `json:"plugin_name"`
	RuleID      string `json:"rule_id"`
	Severity    string `json:"severity"` // 高风险 | 中风险 | 低风险
	Title       string `json:"title"`
	Description string `json:"description"`
	Location    string `json:"location"`
}
